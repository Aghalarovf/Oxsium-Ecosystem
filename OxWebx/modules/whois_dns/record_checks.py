from __future__ import annotations

import ipaddress
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Optional

import dns.flags
import dns.rdatatype

from core.utils import dedupe, load_signature, registered_domain, truncate

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)
CAA_LINE = re.compile(r'^(\d+)\s+([A-Za-z0-9]+)\s+"?(.*?)"?$')
CRITICAL_FLAG = 128


def address_class(value: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    for net in PRIVATE_NETWORKS:
        if net.version == ip.version and ip in net:
            return "private"
    if not ip.is_global:
        return "reserved"
    return "public"


def parse_soa(text: str) -> Optional[dict[str, Any]]:
    tokens = text.split()
    if len(tokens) < 7:
        return None
    try:
        numbers = [int(token) for token in tokens[2:7]]
    except ValueError:
        return None
    return {
        "mname": tokens[0].rstrip(".").lower(),
        "rname": tokens[1].rstrip("."),
        "serial": numbers[0],
        "refresh": numbers[1],
        "retry": numbers[2],
        "expire": numbers[3],
        "minimum": numbers[4],
    }


def soa_mailbox(rname: str) -> Optional[str]:
    match = re.match(r"^((?:[^.\\]|\\.)+)\.(.+)$", rname)
    if not match:
        return None
    return f"{match.group(1).replace(chr(92) + '.', '.')}@{match.group(2)}"


def serial_date(serial: int) -> Optional[datetime]:
    text = str(serial)
    if len(text) != 10:
        return None
    try:
        return datetime(int(text[:4]), int(text[4:6]), int(text[6:8]), tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_caa(records: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for text in records:
        match = CAA_LINE.match(text.strip())
        if not match:
            continue
        entries.append({"flags": int(match.group(1)), "tag": match.group(2).lower(), "value": match.group(3)})
    return entries


def ca_domain(value: str) -> str:
    return value.split(";", 1)[0].strip().lower().rstrip(".")


def mask_secret(text: str) -> str:
    return truncate(text[:6] + "..." if len(text) > 6 else text, 12)


@lru_cache(maxsize=1)
def _vendor_rules() -> list[dict[str, Any]]:
    rules = []
    for vendor in load_signature("dns", "txt_vendors.json")["vendors"]:
        rules.append({**vendor, "regex": re.compile(vendor["pattern"], re.I)})
    return rules


@lru_cache(maxsize=1)
def _generic_token_regex() -> re.Pattern:
    return re.compile(load_signature("dns", "txt_vendors.json")["generic_token_pattern"], re.I)


@lru_cache(maxsize=1)
def _compiled_patterns(kind: str) -> list[tuple[str, re.Pattern]]:
    return [(item["id"], re.compile(item["pattern"])) for item in load_signature("dns", "txt_patterns.json")[kind]]


class RecordAnalysis:
    def _analyze_extended(self, records: dict[str, Any], basic: dict[str, Any]) -> dict[str, Any]:
        analysis: dict[str, Any] = {}
        self._analyze_addresses(basic)
        self._analyze_apex_cname(basic)
        self._analyze_cname_chain(basic)
        analysis["nameservers"] = self._analyze_nameservers(basic)
        self._analyze_mx(records, basic)
        analysis["soa"] = self._analyze_soa_details(basic)
        analysis["txt"] = self._analyze_txt(basic)
        self._analyze_security_records(records)
        analysis["wildcard"] = self._analyze_wildcard(basic)
        self._analyze_record_volume(records)
        return analysis

    def _legacy_probe(self, records: dict[str, Any]) -> list[str]:
        if not self.option("legacy_probe", True):
            return []
        host = self.ctx.target.host
        wanted: list[str] = []
        for rtype in load_signature("dns", "legacy_records.json")["obsolete_types"]:
            if rtype in records:
                continue
            try:
                dns.rdatatype.from_text(rtype)
            except Exception:
                continue
            wanted.append(rtype)
        if not wanted:
            return []
        workers = max(1, int(self.option("threads", 8)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            answers = list(pool.map(lambda t: (t, self.ctx.dns.resolve(host, t)), wanted))
        for rtype, answer in answers:
            records[rtype] = {
                "category": "legacy",
                "status": answer.status,
                "ttl": answer.ttl,
                "records": answer.records,
            }
        return wanted

    def _analyze_addresses(self, basic: dict[str, Any]) -> None:
        host = self.ctx.target.host
        private: list[str] = []
        reserved: list[str] = []
        for value in list(basic["a"]) + list(basic["aaaa"]):
            kind = address_class(value)
            if kind == "private":
                private.append(value)
            elif kind == "reserved":
                reserved.append(value)
        if private:
            self.add(
                "DNS-A-PRIVATE-IP",
                "Address records point to private address space",
                "medium",
                "A or AAAA records resolve to RFC 1918, loopback, link-local or unique-local addresses, which discloses internal addressing and breaks external reachability.",
                {"host": host, "addresses": private},
                confidence="high",
            )
        if reserved:
            self.add(
                "DNS-A-RESERVED-IP",
                "Address records point to reserved or non-routable space",
                "low",
                "A or AAAA records resolve to documentation, benchmarking, shared, multicast or otherwise non-global addresses.",
                {"host": host, "addresses": reserved},
                confidence="high",
            )
        if basic["a"] and not basic["aaaa"] and not self.ctx.target.is_ip:
            self.add(
                "DNS-AAAA-MISSING",
                "No IPv6 address published",
                "info",
                "The host has IPv4 addresses only and is not reachable over IPv6-only networks.",
                {"host": host},
            )

    def _analyze_apex_cname(self, basic: dict[str, Any]) -> None:
        host = self.ctx.target.host
        if basic["zone"] and basic["zone"] == host and basic["cname"]:
            self.add(
                "DNS-APEX-CNAME",
                "CNAME record published at the zone apex",
                "high",
                "A CNAME at the zone apex conflicts with the mandatory SOA and NS records and can break mail delivery and resolver behavior.",
                {"host": host, "cname": basic["cname"]},
                confidence="high",
            )

    def _analyze_cname_chain(self, basic: dict[str, Any]) -> None:
        if not basic["cname"]:
            return
        host = self.ctx.target.host
        chain = self.ctx.dns.cname_chain(host, limit=8)
        if len(chain) >= int(self.option("cname_chain_warn", 3)):
            self.add(
                "DNS-CNAME-CHAIN-LONG",
                f"CNAME chain with {len(chain)} hops",
                "low",
                "Long alias chains add resolution latency and multiply the number of third-party zones that can break or be hijacked.",
                {"host": host, "chain": chain},
            )

    def _analyze_nameservers(self, basic: dict[str, Any]) -> dict[str, Any]:
        nameservers = sorted(set(basic["ns"]))
        zone = basic["zone"]
        result: dict[str, Any] = {"count": len(nameservers), "probes": {}}
        if not zone or not nameservers:
            return result
        if len(nameservers) == 1:
            self.add(
                "DNS-NS-SINGLE",
                "Only one nameserver is delegated",
                "medium",
                "A single authoritative nameserver is a single point of failure for the whole zone.",
                {"zone": zone, "nameservers": nameservers},
                confidence="high",
            )
        prefixes: dict[str, list[str]] = {}
        for ns in nameservers:
            for ip in self.ctx.dns.resolve_ips(ns):
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                length = 24 if address.version == 4 else 48
                network = ipaddress.ip_network(f"{ip}/{length}", strict=False)
                prefixes.setdefault(str(network), []).append(ns)
        if len(nameservers) >= 2 and len(prefixes) == 1:
            self.add(
                "DNS-NS-SAME-NETWORK",
                "All nameservers share one network prefix",
                "low",
                "Nameservers located in the same /24 or /48 prefix fail together during network or provider outages.",
                {"zone": zone, "prefixes": list(prefixes), "nameservers": nameservers},
            )
        if self.option("ns_probe", True):
            result["probes"] = self._probe_nameservers(zone, nameservers)
        return result

    def _probe_nameservers(self, zone: str, nameservers: list[str]) -> dict[str, Any]:
        limit = int(self.option("ns_probe_limit", 8))
        probes: dict[str, Any] = {}
        lame: list[dict[str, str]] = []
        serials: dict[str, int] = {}
        for ns in nameservers[:limit]:
            if not self.ctx.may_contact(ns):
                probes[ns] = {"probed": False, "reason": "out of scope or active checks disabled"}
                continue
            ips = self.ctx.dns.resolve_ips(ns)
            if not ips:
                probes[ns] = {"probed": True, "lame": True, "reason": "unresolvable"}
                lame.append({"ns": ns, "reason": "unresolvable"})
                continue
            response = self.ctx.dns.raw_query(zone, "SOA", ips[0], rd=False)
            reason: Optional[str] = None
            serial: Optional[int] = None
            if response is None:
                reason = "no_response"
            elif response.rcode() != 0:
                reason = f"rcode_{response.rcode()}"
            elif not response.flags & dns.flags.AA:
                reason = "not_authoritative"
            else:
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        serial = list(rrset)[0].serial
                if serial is None:
                    reason = "no_soa"
            probes[ns] = {"probed": True, "lame": reason is not None, "reason": reason, "serial": serial, "ip": ips[0]}
            if reason:
                lame.append({"ns": ns, "reason": reason})
            elif serial is not None:
                serials[ns] = serial
        if lame:
            self.add(
                "DNS-NS-LAME",
                "Lame delegation detected",
                "high",
                "One or more delegated nameservers do not answer authoritatively for the zone, which causes intermittent resolution failures and enables hijacking of unclaimed servers.",
                {"zone": zone, "servers": lame},
                confidence="high",
            )
        if len(set(serials.values())) > 1:
            self.add(
                "DNS-NS-INCONSISTENT-SOA",
                "Nameservers return different SOA serials",
                "medium",
                "Authoritative nameservers disagree on the zone serial, indicating failed zone synchronization and inconsistent answers.",
                {"zone": zone, "serials": serials},
            )
        return probes

    def _analyze_mx(self, records: dict[str, Any], basic: dict[str, Any]) -> None:
        host = self.ctx.target.host
        entries: list[tuple[int, str]] = []
        for item in basic["mx"]:
            preference, _, exchange = item.partition(" ")
            try:
                entries.append((int(preference), exchange.strip().rstrip(".").lower()))
            except ValueError:
                continue
        null_mx = [entry for entry in entries if entry[1] == ""]
        real = [entry for entry in entries if entry[1] != ""]
        if null_mx:
            self.add(
                "DNS-MX-NULL",
                "Null MX record published",
                "info",
                "The domain explicitly declares that it does not accept mail.",
                {"host": host},
                confidence="high",
            )
        if not entries and (basic["a"] or basic["aaaa"]) and not basic["cname"]:
            self.add(
                "DNS-MX-NONE",
                "No MX records published",
                "info",
                "The domain publishes no mail exchangers, so senders fall back to the address records and spoofing protections matter more.",
                {"host": host},
            )
        literal = []
        for _, exchange in real:
            try:
                ipaddress.ip_address(exchange)
                literal.append(exchange)
            except ValueError:
                continue
        if literal:
            self.add(
                "DNS-MX-IP-ADDRESS",
                "MX record points to an IP address",
                "medium",
                "MX targets must be hostnames. An IP literal is invalid and causes delivery failures.",
                {"host": host, "targets": literal},
                confidence="high",
            )
        managed = load_signature("dns", "service_policy.json")["managed_mail_suffixes"]
        if len(real) == 1 and not any(real[0][1] == s or real[0][1].endswith("." + s) for s in managed):
            self.add(
                "DNS-MX-SINGLE",
                "Only one MX record published",
                "low",
                "A single self-managed mail exchanger leaves no fallback when that host is unavailable.",
                {"host": host, "mx": [f"{p} {e}" for p, e in real]},
            )

    def _analyze_soa_details(self, basic: dict[str, Any]) -> dict[str, Any]:
        if not basic["soa"]:
            return {}
        soa = parse_soa(basic["soa"])
        if not soa:
            return {}
        policy = load_signature("dns", "soa_policy.json")
        zone = basic["zone"]
        serial = soa["serial"]
        reasons: list[str] = []
        if serial == 0:
            reasons.append("serial_zero")
        stamp = serial_date(serial)
        if stamp and stamp.year >= int(policy["min_serial_year"]):
            limit = datetime.now(timezone.utc) + timedelta(days=int(policy["max_serial_future_days"]))
            if stamp > limit:
                reasons.append("serial_date_in_future")
        if reasons:
            self.add(
                "DNS-SOA-SERIAL-FORMAT",
                "SOA serial is abnormal",
                "low",
                "The SOA serial is zero or encodes a date in the future, which suggests a misconfigured or manipulated zone.",
                {"zone": zone, "serial": serial, "reasons": reasons},
            )
        violations: list[str] = []
        for key in ("refresh", "retry", "expire"):
            bounds = policy[key]
            value = soa[key]
            if value < bounds["min"]:
                violations.append(f"{key}_below_{bounds['min']}")
            elif value > bounds["max"]:
                violations.append(f"{key}_above_{bounds['max']}")
        if soa["retry"] >= soa["refresh"]:
            violations.append("retry_not_below_refresh")
        if soa["expire"] <= soa["refresh"] + soa["retry"]:
            violations.append("expire_not_above_refresh_plus_retry")
        if violations:
            self.add(
                "DNS-SOA-TIMERS-ABNORMAL",
                "SOA timers are outside recommended ranges",
                "low",
                "Refresh, retry or expire values deviate from RFC 1912 guidance and can cause stale secondary data or excessive transfer load.",
                {"zone": zone, "refresh": soa["refresh"], "retry": soa["retry"], "expire": soa["expire"], "violations": violations},
            )
        mailbox = soa_mailbox(soa["rname"])
        if mailbox:
            local, _, domain = mailbox.partition("@")
            own = registered_domain(domain) == self.ctx.target.registered_domain
            if own or local.lower() not in set(policy["generic_local_parts"]):
                self.add(
                    "DNS-SOA-RNAME-EXPOSED",
                    "SOA RNAME exposes an administrator mailbox",
                    "info",
                    "The SOA record publishes a contact mailbox that can be harvested for phishing or social engineering.",
                    {"zone": zone, "email": mailbox},
                )
        return {"mname": soa["mname"], "rname": soa["rname"], "serial": serial, "mailbox": mailbox}

    def _analyze_txt(self, basic: dict[str, Any]) -> dict[str, Any]:
        host = self.ctx.target.host
        texts = [str(item) for item in basic["txt"]]
        ignore = tuple(load_signature("dns", "txt_patterns.json")["ignore_prefixes"])
        mx_hosts = [h.lower() for h in basic["mx_hosts"]]
        spf_texts = [t.lower() for t in texts if t.lower().startswith("v=spf1")]
        vendors: list[dict[str, Any]] = []
        stale: list[dict[str, Any]] = []
        recognized: set[int] = set()
        for index, text in enumerate(texts):
            for rule in _vendor_rules():
                if not rule["regex"].search(text.strip()):
                    continue
                recognized.add(index)
                entry = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "status": rule["status"],
                    "token": truncate(text, 40),
                }
                vendors.append(entry)
                if rule["status"] != "active":
                    stale.append({**entry, "reason": f"vendor_{rule['status']}", "confidence": "medium"})
                    break
                expected = rule.get("stale_when_absent")
                if expected:
                    mx_ok = any(pattern in h for h in mx_hosts for pattern in expected.get("mx", []))
                    spf_ok = any(pattern in s for s in spf_texts for pattern in expected.get("spf", []))
                    if not mx_ok and not spf_ok:
                        stale.append({**entry, "reason": "no_matching_mail_infrastructure", "confidence": "low"})
                break
        unrecognized = [
            truncate(text, 40)
            for index, text in enumerate(texts)
            if index not in recognized and not text.lower().startswith(ignore) and _generic_token_regex().search(text.strip())
        ]
        if vendors:
            self.add(
                "DNS-TXT-VENDOR-VERIFICATION",
                f"{len(vendors)} third-party verification tokens published",
                "info",
                "Verification tokens in TXT records reveal which SaaS platforms and external services the organization uses.",
                {"host": host, "vendors": vendors, "unrecognized": unrecognized},
                confidence="high",
            )
        if stale:
            self.add(
                "DNS-TXT-STALE-VERIFICATION",
                "Verification tokens for discontinued or unused services",
                "low",
                "Tokens for retired platforms or services without matching mail infrastructure are leftovers that expand the visible footprint and may allow re-verification by a former vendor account.",
                {"host": host, "tokens": stale},
                confidence=stale[0]["confidence"],
            )
        secret_hits: list[dict[str, Any]] = []
        internal_hits: list[dict[str, Any]] = []
        for index, text in enumerate(texts):
            if index in recognized or text.lower().startswith(ignore):
                continue
            secrets = [(pid, rx.search(text)) for pid, rx in _compiled_patterns("secret_patterns")]
            secrets = [(pid, m) for pid, m in secrets if m]
            if secrets:
                secret_hits.append({"patterns": [pid for pid, _ in secrets], "preview": mask_secret(secrets[0][1].group(0))})
            internals = [(pid, rx.search(text)) for pid, rx in _compiled_patterns("internal_patterns")]
            internals = [(pid, m) for pid, m in internals if m]
            if internals:
                internal_hits.append({"patterns": [pid for pid, _ in internals], "match": truncate(internals[0][1].group(0), 60)})
        if secret_hits:
            self.add(
                "DNS-TXT-SECRET-LIKE",
                "TXT record contains credential-like data",
                "high",
                "A TXT record matches a known secret format or a credential assignment. DNS is public, so the value must be treated as compromised.",
                {"host": host, "matches": secret_hits},
                confidence="high" if any(p != "keyword_assignment" for hit in secret_hits for p in hit["patterns"]) else "medium",
            )
        if internal_hits:
            self.add(
                "DNS-TXT-INTERNAL-INFO",
                "TXT record discloses internal details",
                "medium",
                "TXT content references private addresses, internal domains, non-production hostnames or internal notes.",
                {"host": host, "matches": internal_hits},
                confidence="medium",
            )
        total_bytes = sum(len(text.encode("utf-8", errors="replace")) for text in texts)
        limit = int(load_signature("dns", "txt_patterns.json")["oversized_bytes"])
        if total_bytes > limit:
            self.add(
                "DNS-TXT-OVERSIZED",
                f"TXT records total {total_bytes} bytes",
                "low",
                "A large TXT set exceeds typical UDP response size, forces TCP fallback and increases the value of the name for DNS amplification abuse.",
                {"host": host, "bytes": total_bytes, "records": len(texts), "limit": limit},
            )
        seen: dict[str, int] = {}
        for text in texts:
            key = " ".join(text.lower().split())
            seen[key] = seen.get(key, 0) + 1
        duplicates = [truncate(key, 60) for key, count in seen.items() if count > 1]
        if duplicates:
            self.add(
                "DNS-TXT-DUPLICATE",
                "Duplicate TXT records published",
                "info",
                "Identical TXT values are published more than once, which indicates unmanaged record growth.",
                {"host": host, "duplicates": duplicates},
            )
        return {"vendors": vendors, "stale": stale, "unrecognized_tokens": unrecognized, "total_bytes": total_bytes}

    def _analyze_services(self, services: list[dict[str, Any]]) -> None:
        if not services:
            return
        policy = load_signature("dns", "service_policy.json")
        standard = policy["standard_ports"]
        plaintext_prefixes = set(policy["plaintext_prefixes"])
        plaintext_ports = {int(port): name for port, name in policy["plaintext_ports"].items()}
        legacy = policy["legacy_collab_target_patterns"]
        trusted = policy["autodiscover_trusted_suffixes"]
        own = self.ctx.target.registered_domain
        legacy_hits: list[dict[str, Any]] = []
        plain_hits: list[dict[str, Any]] = []
        external: list[dict[str, Any]] = []
        nonstandard: list[dict[str, Any]] = []
        for service in services:
            prefix = service["prefix"]
            for item in service["targets"]:
                target = item["target"]
                port = item["port"]
                if not target:
                    continue
                row = {"name": service["name"], "target": target, "port": port}
                if any(pattern in target for pattern in legacy):
                    legacy_hits.append(row)
                if prefix in plaintext_prefixes or port in plaintext_ports:
                    plain_hits.append({**row, "service": plaintext_ports.get(port, prefix)})
                if prefix == "_autodiscover._tcp":
                    inside = target == own or target.endswith("." + own)
                    allowed = any(target == s or target.endswith("." + s) for s in trusted)
                    if not inside and not allowed:
                        external.append(row)
                expected = standard.get(prefix)
                if expected and port not in expected:
                    nonstandard.append({**row, "expected": expected})
        if legacy_hits:
            self.add(
                "DNS-SRV-LEGACY-COLLAB",
                "SRV records reference legacy collaboration platforms",
                "low",
                "SRV targets point to retired collaboration or unified communications services, which are common sources of dangling infrastructure.",
                {"records": legacy_hits},
            )
        if plain_hits:
            self.add(
                "DNS-SRV-PLAINTEXT-SERVICE",
                "SRV records advertise unencrypted services",
                "medium",
                "Service discovery records point clients to plaintext protocols or ports, enabling credential and content interception.",
                {"records": plain_hits},
            )
        if external:
            self.add(
                "DNS-SRV-AUTODISCOVER-EXTERNAL",
                "Autodiscover is redirected to an external host",
                "low",
                "Mail client configuration is served by a host outside the domain and outside known mail providers, which allows credential capture if that host is compromised.",
                {"records": external},
            )
        if nonstandard:
            self.add(
                "DNS-SRV-PORT-NONSTANDARD",
                "SRV records use non-standard ports",
                "info",
                "Services are advertised on ports that differ from the protocol defaults.",
                {"records": nonstandard},
            )

    def _analyze_caa_policy(self, caa: list[str]) -> None:
        host = self.ctx.target.host
        policy = load_signature("dns", "caa_policy.json")
        entries = parse_caa(caa)
        known = set(policy["known_tags"])
        trusted = set(policy["trusted_cas"])
        wildcard_cas = dedupe(ca_domain(e["value"]) for e in entries if e["tag"] == "issuewild" and ca_domain(e["value"]))
        if len(wildcard_cas) >= int(policy["wildcard_ca_threshold"]):
            self.add(
                "DNS-CAA-WILDCARD-ALLOWED",
                "Wildcard issuance is open to many certificate authorities",
                "low",
                "Several certificate authorities may issue wildcard certificates, which widens the set of parties able to mint certificates for every subdomain.",
                {"host": host, "authorities": wildcard_cas},
            )
        unknown = dedupe(
            ca_domain(e["value"])
            for e in entries
            if e["tag"] in ("issue", "issuewild")
            and ca_domain(e["value"])
            and not any(ca_domain(e["value"]) == t or ca_domain(e["value"]).endswith("." + t) for t in trusted)
        )
        if unknown:
            self.add(
                "DNS-CAA-UNKNOWN-CA",
                "CAA authorizes an unrecognized certificate authority",
                "medium",
                "The CAA policy permits an issuer that is not in the list of known public certificate authorities. This can be a typo, a private CA or an unwanted authorization.",
                {"host": host, "authorities": unknown},
                confidence="low",
            )
        critical = [e for e in entries if e["flags"] & CRITICAL_FLAG and e["tag"] not in known]
        if critical:
            self.add(
                "DNS-CAA-CRITICAL-UNKNOWN",
                "CAA contains a critical flag on an unknown tag",
                "low",
                "A CAA record marked critical with an unrecognized tag forces compliant certificate authorities to refuse issuance entirely.",
                {"host": host, "records": [{"tag": e["tag"], "flags": e["flags"]} for e in critical]},
                confidence="high",
            )

    def _analyze_security_records(self, records: dict[str, Any]) -> None:
        host = self.ctx.target.host
        for rtype in ("HTTPS", "SVCB"):
            for text in self._entry(records, rtype):
                lowered = text.lower()
                if rtype == "HTTPS" and not re.search(r"\bech=", lowered):
                    self.add(
                        "DNS-HTTPS-RR-ECH-MISSING",
                        "HTTPS record does not advertise Encrypted Client Hello",
                        "info",
                        "Without an ECH configuration the TLS server name remains visible to on-path observers.",
                        {"host": host, "record": truncate(text, 120)},
                    )
                alpn = re.search(r'alpn="?([^"\s]+)"?', lowered)
                if alpn:
                    protocols = [p.strip() for p in alpn.group(1).split(",") if p.strip()]
                    if protocols and not any(p == "h2" or p.startswith("h3") for p in protocols):
                        self.add(
                            "DNS-SVCB-ALPN-LEGACY",
                            f"{rtype} record advertises only legacy ALPN protocols",
                            "info",
                            "The service binding does not offer HTTP/2 or HTTP/3.",
                            {"host": host, "type": rtype, "alpn": protocols},
                        )
        policy = load_signature("dns", "legacy_records.json")
        obsolete = [t for t in policy["obsolete_types"] if records.get(t, {}).get("records")]
        if obsolete:
            self.add(
                "DNS-LEGACY-RECORD-PRESENT",
                "Obsolete DNS record types present",
                "low",
                "Records of long-deprecated types remain published, indicating forgotten configuration that can disclose legacy systems.",
                {"host": host, "types": obsolete, "records": {t: records[t]["records"][:3] for t in obsolete}},
            )
        for rtype in policy["location_types"]:
            if records.get(rtype, {}).get("records"):
                self.add(
                    "DNS-LOC-EXPOSED",
                    f"{rtype} record discloses physical location",
                    "low",
                    "Geographic coordinates are published in DNS and reveal the physical location of infrastructure.",
                    {"host": host, "type": rtype, "records": records[rtype]["records"][:3]},
                )
                break
        for rtype in policy["service_listing_types"]:
            if records.get(rtype, {}).get("records"):
                self.add(
                    "DNS-WKS-EXPOSED",
                    f"{rtype} record lists exposed services",
                    "low",
                    "A well-known services record enumerates protocols and ports available on the host.",
                    {"host": host, "type": rtype, "records": records[rtype]["records"][:3]},
                )
                break

    def _analyze_wildcard(self, basic: dict[str, Any]) -> dict[str, Any]:
        probes = int(self.option("wildcard_probes", 3))
        host = self.ctx.target.host
        if probes <= 0 or self.ctx.target.is_ip or not basic["zone"] or not self.ctx.active_allowed:
            return {}
        address_hits: list[str] = []
        mx_hits: list[str] = []
        labels: list[str] = []
        for _ in range(probes):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
            name = f"{label}.{host}"
            labels.append(label)
            addresses = self.ctx.dns.resolve_ips(name)
            if addresses:
                address_hits.extend(addresses)
            if self.ctx.dns.resolve(name, "MX").ok:
                mx_hits.append(name)
        threshold = max(2, probes - 1)
        result: dict[str, Any] = {"probes": probes, "address_hits": len(address_hits), "mx_hits": len(mx_hits)}
        if len(address_hits) >= threshold:
            self.add(
                "DNS-WILDCARD-A",
                "Wildcard address record is active",
                "medium",
                "Random subdomains resolve to an address, so every possible hostname exists. This hides real subdomain enumeration results and enlarges the takeover surface.",
                {"host": host, "addresses": dedupe(address_hits), "probes": probes},
                confidence="high",
            )
        if len(mx_hits) >= threshold:
            self.add(
                "DNS-WILDCARD-MX",
                "Wildcard MX record is active",
                "low",
                "Random subdomains have MX records, so mail for arbitrary subdomains is accepted and can be abused for spoofing or collection.",
                {"host": host, "probes": probes},
                confidence="high",
            )
        return result

    def _analyze_record_volume(self, records: dict[str, Any]) -> None:
        total = sum(len(entry["records"]) for entry in records.values())
        limit = int(self.option("record_count_warn", 30))
        if total >= limit:
            self.add(
                "DNS-ZONE-RECORD-COUNT-HIGH",
                f"{total} records published at one name",
                "info",
                "An unusually large number of records at a single name increases the information available to reconnaissance and may indicate unmanaged growth.",
                {"host": self.ctx.target.host, "total": total, "limit": limit},
            )
