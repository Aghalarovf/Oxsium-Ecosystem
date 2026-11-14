from __future__ import annotations

import base64
import binascii
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

import dns.rdatatype

from core.context import ScanContext
from core.modules import Check
from core.utils import as_list, dedupe, load_signature, registered_domain
from modules.whois_dns.record_checks import RecordAnalysis

MODULE = "whois_dns"


def txt_value(rdata: Any) -> str:
    strings = getattr(rdata, "strings", None)
    if strings is None:
        return rdata.to_text().strip('"')
    return b"".join(strings).decode("utf-8", errors="replace")


def quoted_parts(text: str) -> list[str]:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    return parts if parts else [text.strip()]


def get_basic(ctx: ScanContext) -> dict[str, Any]:
    cached = ctx.recall("whois_dns.basic")
    if cached is not None:
        return cached
    target = ctx.target
    basic: dict[str, Any] = {
        "host": target.host,
        "zone": None,
        "a": [],
        "aaaa": [],
        "ns": [],
        "mx": [],
        "mx_hosts": [],
        "cname": [],
        "txt": [],
        "soa": None,
    }
    if target.is_ip:
        basic["aaaa" if ":" in target.host else "a"] = [target.host]
        ctx.share("whois_dns.basic", basic)
        return basic
    host = target.host
    basic["a"] = list(ctx.dns.resolve(host, "A").records)
    basic["aaaa"] = list(ctx.dns.resolve(host, "AAAA").records)
    basic["cname"] = [r.rstrip(".") for r in ctx.dns.resolve(host, "CNAME").records]
    mx = ctx.dns.resolve(host, "MX")
    for rdata in mx.rdata:
        exchange = str(rdata.exchange).rstrip(".")
        basic["mx"].append(f"{rdata.preference} {exchange}")
        if exchange:
            basic["mx_hosts"].append(exchange.lower())
    basic["txt"] = [txt_value(r) for r in ctx.dns.resolve(host, "TXT").rdata]
    zone = ctx.dns.find_zone(host)
    basic["zone"] = zone
    if zone:
        basic["ns"] = [r.rstrip(".").lower() for r in ctx.dns.resolve(zone, "NS").records]
        soa = ctx.dns.resolve(zone, "SOA")
        if soa.records:
            basic["soa"] = soa.records[0]
    ctx.share("whois_dns.basic", basic)
    return basic


def get_addresses(ctx: ScanContext) -> list[str]:
    basic = get_basic(ctx)
    return dedupe(list(basic["a"]) + list(basic["aaaa"]))


def parse_tags(text: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in text.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


class RecordsCheck(RecordAnalysis, Check):
    module = MODULE
    name = "records"
    description = "DNS record enumeration with record hygiene analysis"
    passive = True
    domain_only = True

    def types(self) -> list[str]:
        signature = load_signature("dns", "record_types.json")
        names: list[str] = []
        for category in as_list(self.option("categories", ["core", "security", "service"])):
            names.extend(signature["categories"].get(category, []))
        names.extend(t.upper() for t in as_list(self.option("extra_types", [])))
        supported: list[str] = []
        for rtype in dedupe(names):
            try:
                dns.rdatatype.from_text(rtype)
            except Exception:
                continue
            supported.append(rtype)
        return supported

    def category_of(self, rtype: str) -> str:
        signature = load_signature("dns", "record_types.json")
        for category, members in signature["categories"].items():
            if rtype in members:
                return category
        return "extra"

    def run(self) -> dict[str, Any]:
        host = self.ctx.target.host
        types = self.types()
        workers = max(1, int(self.option("threads", 8)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            answers = list(pool.map(lambda t: (t, self.ctx.dns.resolve(host, t)), types))
        records: dict[str, Any] = {}
        for rtype, answer in answers:
            records[rtype] = {
                "category": self.category_of(rtype),
                "status": answer.status,
                "ttl": answer.ttl,
                "records": answer.records,
            }
        statuses = {entry["status"] for entry in records.values()}
        if records and statuses <= {"timeout", "error", "servfail"}:
            self.fail("no usable DNS responses, resolver may be unreachable or blocked")
        probed = self._legacy_probe(records)
        nxdomain = any(entry["status"] == "nxdomain" for entry in records.values())
        if nxdomain:
            self.add(
                "DNS-NXDOMAIN",
                "Domain does not resolve (NXDOMAIN)",
                "medium",
                f"{host} returned NXDOMAIN for the queried record types.",
                {"host": host},
            )
        basic = get_basic(self.ctx)
        data: dict[str, Any] = {
            "host": host,
            "zone": basic["zone"],
            "types_queried": len(types) + len(probed),
            "types_with_data": sum(1 for e in records.values() if e["records"]),
            "nxdomain": nxdomain,
            "records": records,
            "summary": {k: basic[k] for k in ("a", "aaaa", "ns", "mx", "cname", "txt", "soa")},
        }
        self._analyze_caa(records, basic)
        self._analyze_hinfo(records)
        self._analyze_rp(records)
        self._analyze_naptr(records)
        self._analyze_soa(basic)
        data["analysis"] = self._analyze_extended(records, basic)
        if self.option("discover_services", True):
            data["services"] = self._discover_services()
        return data

    def _entry(self, records: dict[str, Any], rtype: str) -> list[str]:
        if rtype in records:
            return records[rtype]["records"]
        return self.ctx.dns.resolve(self.ctx.target.host, rtype).records

    def _analyze_caa(self, records: dict[str, Any], basic: dict[str, Any]) -> None:
        host = self.ctx.target.host
        if basic["zone"] and basic["zone"] != host:
            return
        caa = self._entry(records, "CAA")
        if not caa:
            if basic["a"] or basic["aaaa"] or basic["ns"]:
                self.add(
                    "DNS-CAA-MISSING",
                    "No CAA records published",
                    "low",
                    "Any certificate authority may issue certificates for this domain.",
                    {"host": host},
                )
            return
        self._analyze_caa_policy(caa)
        tags: dict[str, list[str]] = {}
        for text in caa:
            match = re.match(r'^\d+\s+(\w+)\s+"?(.*?)"?$', text.strip())
            if match:
                tags.setdefault(match.group(1).lower(), []).append(match.group(2))
        if "issue" in tags and "issuewild" not in tags:
            self.add(
                "DNS-CAA-NO-ISSUEWILD",
                "CAA has no issuewild policy",
                "info",
                "Wildcard certificates follow the generic issue policy.",
                {"tags": tags},
            )
        if "iodef" not in tags:
            self.add(
                "DNS-CAA-NO-IODEF",
                "CAA has no iodef contact",
                "info",
                "No incident reporting endpoint is configured for certificate issuance violations.",
                {"tags": tags},
            )

    def _analyze_hinfo(self, records: dict[str, Any]) -> None:
        for text in self._entry(records, "HINFO"):
            parts = quoted_parts(text)
            self.add(
                "DNS-HINFO-EXPOSED",
                "HINFO record exposes host details",
                "low",
                "HINFO publishes hardware or operating system information.",
                {"cpu": parts[0] if parts else "", "os": parts[1] if len(parts) > 1 else ""},
            )

    def _analyze_rp(self, records: dict[str, Any]) -> None:
        for text in self._entry(records, "RP"):
            tokens = text.split()
            if not tokens:
                continue
            mailbox = tokens[0].rstrip(".")
            local, _, rest = mailbox.partition(".")
            email = f"{local}@{rest}" if rest else mailbox
            self.add(
                "DNS-RP-CONTACT",
                "RP record exposes a responsible person mailbox",
                "info",
                "A contact mailbox is published in DNS.",
                {"email": email, "txt_reference": tokens[1].rstrip(".") if len(tokens) > 1 else ""},
            )

    def _analyze_naptr(self, records: dict[str, Any]) -> None:
        services = set(load_signature("dns", "record_types.json")["voip_naptr_services"])
        found: list[str] = []
        for text in self._entry(records, "NAPTR"):
            parts = quoted_parts(text)
            for part in parts:
                if part.upper() in services:
                    found.append(part.upper())
        if found:
            self.add(
                "DNS-NAPTR-VOIP",
                "VoIP services advertised through NAPTR",
                "info",
                "NAPTR records reveal SIP infrastructure.",
                {"services": dedupe(found)},
            )

    def _analyze_soa(self, basic: dict[str, Any]) -> None:
        if not basic["soa"]:
            return
        tokens = basic["soa"].split()
        if len(tokens) < 7:
            return
        try:
            refresh, retry, expire, minimum = (int(tokens[3]), int(tokens[4]), int(tokens[5]), int(tokens[6]))
        except ValueError:
            return
        if minimum > 3600:
            self.add(
                "DNS-SOA-NEGATIVE-TTL",
                "High SOA negative caching TTL",
                "low",
                "NXDOMAIN answers can persist in resolver caches for a long time, which delays recovery after a takeover or typo fix.",
                {"minimum": minimum, "refresh": refresh, "retry": retry, "expire": expire},
            )

    def _discover_services(self) -> list[dict[str, Any]]:
        signature = load_signature("dns", "record_types.json")
        prefixes = signature["srv_prefixes"]
        directory = set(signature["directory_service_prefixes"])
        zone = get_basic(self.ctx)["zone"] or self.ctx.target.host
        workers = max(1, int(self.option("threads", 8)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda p: (p, self.ctx.dns.resolve(f"{p}.{zone}", "SRV")), prefixes))
        services: list[dict[str, Any]] = []
        for prefix, answer in results:
            if not answer.ok:
                continue
            targets = []
            for rdata in answer.rdata:
                targets.append({
                    "target": str(rdata.target).rstrip(".").lower(),
                    "port": rdata.port,
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                })
            services.append({"name": f"{prefix}.{zone}", "prefix": prefix, "targets": targets})
        self.ctx.share("whois_dns.srv", services)
        self._analyze_services(services)
        if any(s["prefix"] in directory for s in services):
            self.add(
                "DNS-SRV-DIRECTORY",
                "Directory service records exposed in DNS",
                "medium",
                "LDAP or Kerberos SRV records indicate an Active Directory style environment and reveal domain controller hostnames.",
                {"records": [s["name"] for s in services if s["prefix"] in directory]},
            )
        elif services:
            self.add(
                "DNS-SRV-EXPOSED",
                "Service discovery records published",
                "info",
                "SRV records reveal service hostnames and ports.",
                {"records": [s["name"] for s in services]},
            )
        return services


class EmailSecurityCheck(Check):
    module = MODULE
    name = "email_security"
    description = "SPF, DMARC, DKIM, MTA-STS and related mail policy analysis"
    passive = True
    domain_only = True

    def run(self) -> dict[str, Any]:
        basic = get_basic(self.ctx)
        host = self.ctx.target.host
        domain = basic["zone"] or host
        real_mx = [m for m in basic["mx"] if not m.endswith(" ") and m.split(" ", 1)[-1] not in ("", ".")]
        has_mx = bool(real_mx)
        missing_severity = "medium" if has_mx else "low"
        spf = self._spf(host, basic, missing_severity)
        dmarc = self._dmarc(host, domain, missing_severity)
        dkim = self._dkim(domain) if self.option("dkim_probe", True) else {"probed": False, "selectors": []}
        mta_sts = self._mta_sts(domain)
        tls_rpt = self._tls_rpt(domain)
        bimi = self._bimi(domain, dmarc.get("policy"))
        if has_mx and dkim.get("probed") and not dkim["selectors"]:
            self.add(
                "EMAIL-DKIM-MISSING",
                "No DKIM selector found",
                "low",
                "The domain receives mail but none of the common DKIM selectors publish a key. Mail may be sent unsigned or with a custom selector that could not be discovered.",
                {"domain": domain, "selectors_tested": dkim.get("selectors_tested", 0)},
                confidence="low",
            )
        if has_mx and not tls_rpt["present"]:
            self.add(
                "EMAIL-TLSRPT-MISSING",
                "No TLS-RPT record",
                "info",
                "Without SMTP TLS reporting, delivery failures and downgrade attacks against inbound mail go unnoticed.",
                {"domain": domain, "mta_sts": mta_sts["present"]},
            )
        return {
            "domain": domain,
            "has_mx": has_mx,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "mta_sts": mta_sts,
            "tls_rpt": tls_rpt,
            "bimi": bimi,
        }

    def _txt(self, name: str) -> list[str]:
        return [txt_value(r) for r in self.ctx.dns.resolve(name, "TXT").rdata]

    def _spf(self, host: str, basic: dict[str, Any], missing_severity: str) -> dict[str, Any]:
        records = [t for t in basic["txt"] if t.lower().startswith("v=spf1")]
        result: dict[str, Any] = {"records": records, "present": bool(records)}
        if not records:
            self.add(
                "EMAIL-SPF-MISSING",
                "No SPF record",
                missing_severity,
                "Without SPF, receivers cannot verify which servers may send mail for this domain.",
                {"host": host},
            )
            return result
        if len(records) > 1:
            self.add(
                "EMAIL-SPF-MULTIPLE",
                "Multiple SPF records published",
                "high",
                "More than one SPF record causes a permanent error and SPF evaluation fails.",
                {"records": records},
            )
        record = records[0]
        parsed = self._parse_spf(record)
        analysis = self._spf_analysis(record, host)
        lookups = analysis["lookups"]
        result.update({
            "all_qualifier": parsed["all"],
            "includes": parsed["includes"],
            "redirect": parsed["redirect"],
            "mechanisms": parsed["mechanisms"],
            "dns_lookups": lookups,
            "void_lookups": analysis["voids"],
            "include_loops": analysis["loops"],
        })
        if parsed["all"] == "+":
            self.add("EMAIL-SPF-PASS-ALL", "SPF allows any sender (+all)", "high", "The policy authorizes every host on the internet to send mail for the domain.", {"record": record})
        elif parsed["all"] == "?":
            self.add("EMAIL-SPF-NEUTRAL-ALL", "SPF uses neutral qualifier (?all)", "medium", "A neutral result provides no protection against spoofing.", {"record": record})
        elif parsed["all"] == "~":
            self.add("EMAIL-SPF-SOFTFAIL", "SPF uses softfail (~all)", "info", "Softfail marks spoofed mail suspicious but does not request rejection.", {"record": record})
        elif parsed["all"] is None and not parsed["redirect"]:
            self.add("EMAIL-SPF-NO-ALL", "SPF has no terminating all mechanism", "medium", "Senders not matched by any mechanism receive a neutral result.", {"record": record})
        if lookups > 10:
            self.add("EMAIL-SPF-LOOKUPS", "SPF exceeds the 10 DNS lookup limit", "medium", f"Estimated {lookups} lookups; evaluation fails with a permanent error above 10.", {"lookups": lookups})
        if analysis["loops"]:
            self.add("EMAIL-SPF-INCLUDE-LOOP", "SPF include chain contains a loop", "medium", "A circular include or redirect makes SPF evaluation fail with a permanent error.", {"loops": analysis["loops"]})
        if analysis["voids"] > 2:
            self.add("EMAIL-SPF-VOID-LOOKUPS", "SPF exceeds the void lookup limit", "low", "More than two mechanisms reference names that return no data, which RFC 7208 treats as a permanent error.", {"void_lookups": analysis["voids"]})
        if "ptr" in parsed["mechanisms"]:
            self.add("EMAIL-SPF-PTR", "SPF uses the deprecated ptr mechanism", "low", "RFC 7208 discourages the ptr mechanism.", {"record": record})
        return result

    def _parse_spf(self, record: str) -> dict[str, Any]:
        mechanisms: list[str] = []
        includes: list[str] = []
        all_qualifier: Optional[str] = None
        redirect: Optional[str] = None
        for token in record.split()[1:]:
            lowered = token.lower()
            if lowered.startswith("redirect="):
                redirect = token.split("=", 1)[1]
                continue
            if lowered.startswith("exp="):
                continue
            qualifier = "+"
            if token[0] in "+-~?":
                qualifier, token = token[0], token[1:]
            match = re.match(r"^([a-z0-9]+)(?:[:/=](.*))?$", token, re.I)
            if not match:
                continue
            name = match.group(1).lower()
            value = match.group(2)
            mechanisms.append(name)
            if name == "all":
                all_qualifier = qualifier
            elif name == "include" and value:
                includes.append(value.lower())
        return {"all": all_qualifier, "includes": includes, "redirect": redirect, "mechanisms": mechanisms}

    def _spf_analysis(self, record: str, domain: str) -> dict[str, Any]:
        state: dict[str, Any] = {"lookups": 0, "voids": 0, "loops": [], "budget": 20, "domain": domain}
        self._spf_walk(record, [domain], state, 0)
        return {key: state[key] for key in ("lookups", "voids", "loops")}

    def _spf_walk(self, record: str, chain: list[str], state: dict[str, Any], depth: int) -> None:
        if depth > 6:
            return
        for token in record.split()[1:]:
            lowered = token.lstrip("+-~?").lower()
            name = re.split(r"[:/=]", lowered, maxsplit=1)[0]
            if name in ("a", "mx", "ptr", "exists"):
                state["lookups"] += 1
                if name == "ptr" or state["budget"] <= 0:
                    continue
                target = lowered.split(":", 1)[1].split("/")[0] if ":" in lowered else state["domain"]
                state["budget"] -= 1
                if name == "a":
                    empty = not self.ctx.dns.resolve_ips(target)
                elif name == "mx":
                    empty = not self.ctx.dns.resolve(target, "MX").ok
                else:
                    empty = not self.ctx.dns.resolve(target, "A").ok
                if empty:
                    state["voids"] += 1
            elif name in ("include", "redirect") and (":" in lowered or "=" in lowered):
                state["lookups"] += 1
                target = re.split(r"[:=]", lowered, maxsplit=1)[1]
                if target in chain:
                    state["loops"].append(" -> ".join(chain + [target]))
                    continue
                if state["budget"] <= 0:
                    continue
                state["budget"] -= 1
                nested = next((t for t in self._txt(target) if t.lower().startswith("v=spf1")), None)
                if nested is None:
                    state["voids"] += 1
                    continue
                self._spf_walk(nested, chain + [target], state, depth + 1)

    def _dmarc(self, host: str, domain: str, missing_severity: str) -> dict[str, Any]:
        candidates = dedupe([f"_dmarc.{host}", f"_dmarc.{domain}", f"_dmarc.{registered_domain(host)}"])
        record = None
        used = None
        for name in candidates:
            for text in self._txt(name):
                if text.lower().startswith("v=dmarc1"):
                    record, used = text, name
                    break
            if record:
                break
        result: dict[str, Any] = {"present": bool(record), "record": record, "name": used}
        if not record:
            self.add(
                "EMAIL-DMARC-MISSING",
                "No DMARC record",
                missing_severity,
                "Without DMARC, spoofed mail is not subject to a domain owner policy and no reports are produced.",
                {"queried": candidates},
            )
            return result
        tags = parse_tags(record)
        policy = tags.get("p", "").lower()
        sub_policy = tags.get("sp", "").lower()
        pct = tags.get("pct", "100")
        result.update({"policy": policy, "subdomain_policy": sub_policy or None, "pct": pct, "rua": tags.get("rua"), "ruf": tags.get("ruf"), "tags": tags})
        if policy == "none":
            self.add("EMAIL-DMARC-MONITOR", "DMARC policy is monitor only (p=none)", "low", "Spoofed mail is reported but not quarantined or rejected.", {"record": record})
        if sub_policy == "none" and policy in ("quarantine", "reject"):
            self.add("EMAIL-DMARC-SUBDOMAIN-WEAK", "DMARC subdomain policy is monitor only", "low", "Subdomains can be spoofed even though the main domain is protected.", {"record": record})
        try:
            share = int(pct)
        except ValueError:
            share = 100
        if share < 100 and policy in ("quarantine", "reject"):
            if share < 50:
                self.add("EMAIL-DMARC-PCT-LOW", "DMARC applies to a minority of mail", "low", f"pct={pct} leaves most failing mail unaffected by the published policy.", {"record": record, "pct": share})
            else:
                self.add("EMAIL-DMARC-PARTIAL", "DMARC applies to only part of the mail", "low", f"pct={pct} leaves the remaining share of failing mail unaffected.", {"record": record})
        if not tags.get("rua"):
            self.add("EMAIL-DMARC-NO-RUA", "DMARC has no aggregate report address", "info", "No rua tag is published.", {"record": record})
        return result

    def _dkim(self, domain: str) -> dict[str, Any]:
        signature = load_signature("dns", "dkim_selectors.json")
        selectors = signature["selectors"]
        providers = signature["providers"]
        workers = max(1, int(self.option("dkim_threads", 10)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda s: (s, self._txt(f"{s}._domainkey.{domain}")), selectors))
        found: list[dict[str, Any]] = []
        for selector, texts in results:
            for text in texts:
                tags = parse_tags(text)
                if "p" not in tags and not text.lower().startswith("v=dkim1"):
                    continue
                entry = self._dkim_entry(selector, tags, providers.get(selector))
                found.append(entry)
                self._dkim_findings(domain, entry)
        return {"probed": True, "selectors_tested": len(selectors), "selectors": found}

    def _dkim_entry(self, selector: str, tags: dict[str, str], provider: Optional[str]) -> dict[str, Any]:
        key_type = tags.get("k", "rsa").lower()
        public = tags.get("p", "").replace(" ", "")
        bits: Optional[int] = None
        revoked = public == ""
        if public and key_type == "rsa":
            try:
                size = len(base64.b64decode(public + "=" * (-len(public) % 4)))
                bits = 512 if size <= 100 else 768 if size <= 135 else 1024 if size <= 175 else 2048 if size <= 310 else 4096
            except (binascii.Error, ValueError):
                bits = None
        return {
            "selector": selector,
            "provider": provider,
            "key_type": key_type,
            "approx_bits": bits,
            "revoked": revoked,
            "testing": "y" in tags.get("t", "").lower().split(":"),
        }

    def _dkim_findings(self, domain: str, entry: dict[str, Any]) -> None:
        bits = entry["approx_bits"]
        if bits is not None and bits < 1024:
            self.add("EMAIL-DKIM-WEAK-KEY", f"DKIM key below 1024 bits ({entry['selector']})", "high", "RFC 8301 requires at least 1024-bit RSA keys.", entry)
        elif bits == 1024:
            self.add("EMAIL-DKIM-1024", f"DKIM key is 1024-bit RSA ({entry['selector']})", "low", "2048-bit keys are recommended.", entry)
        if entry["testing"]:
            self.add("EMAIL-DKIM-TESTING", f"DKIM selector in testing mode ({entry['selector']})", "low", "The t=y flag tells verifiers not to treat failures as meaningful.", entry)

    def _mta_sts(self, domain: str) -> dict[str, Any]:
        records = [t for t in self._txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
        result: dict[str, Any] = {"present": bool(records), "record": records[0] if records else None, "policy": None}
        if not records:
            return result
        host = f"mta-sts.{domain}"
        if not (self.option("mta_sts_fetch", True) and self.ctx.may_contact(host)):
            return result
        response = self.ctx.http.get(f"https://{host}/.well-known/mta-sts.txt", max_body=16384)
        if response.status != 200:
            self.add("EMAIL-MTASTS-POLICY-UNREACHABLE", "MTA-STS policy file is not reachable", "low", "The _mta-sts TXT record exists but the policy file could not be fetched.", {"status": response.status, "error": response.error})
            return result
        policy: dict[str, Any] = {"mx": []}
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key, value = key.strip().lower(), value.strip()
            if key == "mx":
                policy["mx"].append(value)
            else:
                policy[key] = value
        result["policy"] = policy
        if policy.get("mode", "").lower() in ("testing", "none"):
            self.add("EMAIL-MTASTS-NOT-ENFORCED", "MTA-STS is not enforcing", "low", f"Policy mode is {policy.get('mode')}.", {"policy": policy})
        return result

    def _tls_rpt(self, domain: str) -> dict[str, Any]:
        records = [t for t in self._txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
        return {"present": bool(records), "record": records[0] if records else None}

    def _bimi(self, domain: str, dmarc_policy: Optional[str] = None) -> dict[str, Any]:
        records = [t for t in self._txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
        result: dict[str, Any] = {"present": bool(records), "record": records[0] if records else None, "issues": []}
        if not records:
            return result
        tags = parse_tags(records[0])
        issues: list[str] = []
        logo = tags.get("l", "")
        if not logo.lower().startswith("https://"):
            issues.append("logo_url_missing_or_not_https")
        if dmarc_policy not in ("quarantine", "reject"):
            issues.append("dmarc_not_enforcing")
        result["issues"] = issues
        if issues:
            self.add("EMAIL-BIMI-INVALID", "BIMI record is not valid", "low", "BIMI requires an HTTPS logo location and an enforcing DMARC policy; otherwise mailbox providers ignore the record.", {"record": records[0], "issues": issues})
        return result


class TtlAnomalyCheck(Check):
    module = MODULE
    name = "ttl_anomaly"
    description = "TTL threshold, TTL variance and authoritative IP rotation analysis for fast-flux detection"
    passive = False
    domain_only = True

    def run(self) -> dict[str, Any]:
        host = self.ctx.target.host
        low_ttl = int(self.option("low_ttl", 300))
        very_low_ttl = int(self.option("very_low_ttl", 60))
        snapshot: dict[str, Any] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            answer = self.ctx.dns.resolve(host, rtype)
            if answer.ok:
                snapshot[rtype] = {"ttl": answer.ttl, "records": answer.records}
        self._threshold_findings(snapshot, low_ttl, very_low_ttl)
        self._role_findings(snapshot, low_ttl)
        self._asymmetry_findings(snapshot)
        rotation: dict[str, Any] = {}
        if self.ctx.may_contact(host) and any(rtype in snapshot for rtype in ("A", "AAAA")):
            rotation = self._rotation(host)
            self._analyze_rotation(rotation)
        consistency = self._consistency(snapshot)
        return {"snapshot": snapshot, "rotation": rotation, "consistency": consistency}

    def _threshold_findings(self, snapshot: dict[str, Any], low_ttl: int, very_low_ttl: int) -> None:
        for rtype, entry in snapshot.items():
            ttl = entry.get("ttl")
            if ttl is None:
                continue
            if ttl <= 1:
                self.add(
                    "TTL-CRITICAL",
                    f"{rtype} TTL is {ttl}s",
                    "high",
                    "A TTL at or near zero is unusual and can indicate fast-flux infrastructure or active DNS manipulation.",
                    {"type": rtype, "ttl": ttl},
                )
            elif ttl < very_low_ttl:
                self.add(
                    "TTL-VERY-LOW",
                    f"{rtype} TTL is below {very_low_ttl}s",
                    "medium",
                    "A very low TTL forces frequent re-resolution, which is characteristic of fast-flux hosting used to resist takedown.",
                    {"type": rtype, "ttl": ttl},
                )
            elif ttl < low_ttl:
                self.add(
                    "TTL-LOW",
                    f"{rtype} TTL is below {low_ttl}s",
                    "info",
                    "A low TTL is sometimes legitimate for load balancing or failover, but is worth monitoring.",
                    {"type": rtype, "ttl": ttl},
                )

    def _role_findings(self, snapshot: dict[str, Any], low_ttl: int) -> None:
        limits = {
            "NS": ("TTL-NS-LOW", int(self.option("ns_low_ttl", 3600))),
            "MX": ("TTL-MX-LOW", int(self.option("mx_low_ttl", 600))),
        }
        for rtype, (finding_id, limit) in limits.items():
            ttl = snapshot.get(rtype, {}).get("ttl")
            if ttl is None or ttl < low_ttl or ttl >= limit:
                continue
            self.add(
                finding_id,
                f"{rtype} TTL is {ttl}s",
                "low",
                f"{rtype} records normally use long TTLs. A short value increases query load on authoritative servers and shortens the window to detect tampering.",
                {"type": rtype, "ttl": ttl, "threshold": limit},
            )

    def _asymmetry_findings(self, snapshot: dict[str, Any]) -> None:
        v4 = snapshot.get("A", {}).get("ttl")
        v6 = snapshot.get("AAAA", {}).get("ttl")
        if v4 is None or v6 is None or v4 == v6:
            return
        self.add(
            "TTL-ASYMMETRIC",
            "A and AAAA records use different TTLs",
            "info",
            "IPv4 and IPv6 records of the same host are cached for different periods, which causes inconsistent failover behavior.",
            {"a_ttl": v4, "aaaa_ttl": v6},
        )

    def _ns_ips(self, host: str) -> list[str]:
        zone = get_basic(self.ctx)["zone"] or host
        ns_records = self.ctx.dns.resolve(zone, "NS").records
        ips: list[str] = []
        for ns in ns_records:
            ips.extend(self.ctx.dns.resolve_ips(ns.rstrip(".")))
        return dedupe(ips) or list(self.ctx.dns.nameservers)

    def _rotation(self, host: str) -> dict[str, Any]:
        probes = int(self.option("probes", 5))
        delay = float(self.option("probe_delay", 2.0))
        ns_ips = self._ns_ips(host)
        if not ns_ips:
            return {}
        rounds: list[dict[str, Any]] = []
        all_ips: set[str] = set()
        for i in range(probes):
            round_ips: set[str] = set()
            for rtype in ("A", "AAAA"):
                server = ns_ips[i % len(ns_ips)]
                response = self.ctx.dns.raw_query(host, rtype, server, rd=False)
                if response is None:
                    continue
                wanted = dns.rdatatype.from_text(rtype)
                for rrset in response.answer:
                    if rrset.rdtype == wanted:
                        round_ips.update(rdata.to_text() for rdata in rrset)
            all_ips.update(round_ips)
            rounds.append({"round": i + 1, "ips": sorted(round_ips)})
            if i < probes - 1 and delay > 0:
                time.sleep(delay)
        return {"rounds": rounds, "unique_ips": sorted(all_ips)}

    def _analyze_rotation(self, rotation: dict[str, Any]) -> None:
        unique = rotation.get("unique_ips") or []
        warn_count = int(self.option("ip_warn", 4))
        crit_count = int(self.option("ip_crit", 8))
        if len(unique) >= crit_count:
            self.add(
                "TTL-FASTFLUX-CONFIRMED",
                "Fast-flux IP rotation confirmed",
                "critical",
                f"{len(unique)} unique IP addresses were observed across repeated queries sent directly to the authoritative nameservers, consistent with fast-flux hosting.",
                rotation,
            )
        elif len(unique) >= warn_count:
            self.add(
                "TTL-FASTFLUX-SUSPECTED",
                "Suspicious IP rotation detected",
                "medium",
                f"{len(unique)} unique IP addresses were observed across repeated authoritative queries.",
                rotation,
            )

    def _consistency(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        ttls = {rtype: entry["ttl"] for rtype, entry in snapshot.items() if entry.get("ttl")}
        if len(ttls) < 2:
            return {}
        min_type = min(ttls, key=ttls.get)
        max_type = max(ttls, key=ttls.get)
        ratio = ttls[max_type] / ttls[min_type] if ttls[min_type] else float("inf")
        result = {
            "min_type": min_type,
            "min_ttl": ttls[min_type],
            "max_type": max_type,
            "max_ttl": ttls[max_type],
            "ratio": round(ratio, 1),
        }
        if ratio > 1000:
            self.add(
                "TTL-INCONSISTENT",
                "Large TTL disparity across record types",
                "medium",
                f"The TTL ratio between {max_type} and {min_type} is {ratio:.0f}x, which is unusual and may indicate manipulation of one record type.",
                result,
            )
        return result