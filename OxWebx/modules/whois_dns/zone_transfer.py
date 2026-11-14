from __future__ import annotations

import random
import string
from typing import Any, Optional

import dns.exception
import dns.query
import dns.rdatatype
import dns.zone

from core.context import ScanContext
from core.modules import Check
from core.utils import dedupe, load_signature, registered_domain
from modules.whois_dns.records import get_basic
from modules.whois_dns.whois import registration_state

MODULE = "whois_dns"


def resolve_ns_ip(ctx: ScanContext, ns: str) -> Optional[str]:
    ips = ctx.dns.resolve_ips(ns)
    return ips[0] if ips else None


class ZoneTransferCheck(Check):
    module = MODULE
    name = "zone_transfer"
    description = "AXFR/IXFR zone transfer and legacy ANY query exposure testing"
    passive = False
    domain_only = True

    def run(self) -> dict[str, Any]:
        basic = get_basic(self.ctx)
        zone = basic["zone"] or self.ctx.target.host
        nameservers = basic["ns"]
        if not nameservers:
            self.fail("no authoritative nameservers found for zone")
            return {"zone": zone, "servers": {}, "vulnerable": False}
        max_servers = int(self.option("max_servers", 8))
        timeout = float(self.option("timeout", 10))
        lifetime = float(self.option("lifetime", 30))
        max_records = int(self.option("max_records", 5000))
        try_ixfr = bool(self.option("try_ixfr", True))
        any_query = bool(self.option("any_query", True))
        servers: dict[str, Any] = {}
        vulnerable_servers: list[str] = []
        for ns in nameservers[:max_servers]:
            if not self.ctx.may_contact(ns):
                servers[ns] = {"attempted": False, "reason": "out of scope or active checks disabled"}
                continue
            entry = self._attempt(ns, zone, timeout, lifetime, max_records, try_ixfr, any_query)
            servers[ns] = entry
            if entry.get("vulnerable"):
                vulnerable_servers.append(ns)
        if vulnerable_servers:
            self.add(
                "ZONE-TRANSFER-ALLOWED",
                "Zone transfer (AXFR/IXFR) succeeded",
                "critical",
                "An unauthenticated zone transfer disclosed the full contents of the zone, including internal hosts and infrastructure that are not otherwise publicly discoverable.",
                {"nameservers": vulnerable_servers, "zone": zone},
            )
        for ns, entry in servers.items():
            if entry.get("any_records"):
                self.add(
                    "DNS-ANY-DISCLOSURE",
                    "ANY query returned multiple record types",
                    "low",
                    "A legacy ANY query returned several record types in a single response, which can assist reconnaissance and DNS amplification abuse.",
                    {"nameserver": ns, "records": entry["any_records"][:20]},
                )
        return {"zone": zone, "servers": servers, "vulnerable": bool(vulnerable_servers)}

    def _attempt(
        self,
        ns: str,
        zone: str,
        timeout: float,
        lifetime: float,
        max_records: int,
        try_ixfr: bool,
        any_query: bool,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {"attempted": True, "vulnerable": False, "record_count": 0, "any_records": [], "error": None}
        ns_ip = resolve_ns_ip(self.ctx, ns)
        if not ns_ip:
            entry["error"] = "could not resolve nameserver address"
            return entry
        records = self._axfr(ns_ip, zone, timeout, lifetime, max_records)
        if records is None and try_ixfr:
            records = self._ixfr(ns_ip, zone, timeout, lifetime, max_records)
        if records is not None:
            entry["vulnerable"] = True
            entry["record_count"] = len(records)
            entry["sample"] = records[:50]
            return entry
        if any_query:
            entry["any_records"] = self._any(ns_ip, zone, timeout)
        return entry

    def _axfr(self, ns_ip: str, zone: str, timeout: float, lifetime: float, max_records: int) -> Optional[list[str]]:
        try:
            xfr = dns.query.xfr(ns_ip, zone, timeout=timeout, lifetime=lifetime)
            zobj = dns.zone.from_xfr(xfr)
        except (dns.exception.FormError, dns.exception.DNSException, OSError):
            return None
        return self._flatten(zobj, zone, max_records)

    def _ixfr(self, ns_ip: str, zone: str, timeout: float, lifetime: float, max_records: int) -> Optional[list[str]]:
        serial = 0
        soa_response = self.ctx.dns.raw_query(zone, "SOA", ns_ip, timeout=timeout)
        if soa_response is not None:
            for rrset in soa_response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    serial = list(rrset)[0].serial
        try:
            xfr = dns.query.xfr(ns_ip, zone, rdtype=dns.rdatatype.IXFR, serial=serial, timeout=timeout, lifetime=lifetime)
            zobj = dns.zone.from_xfr(xfr)
        except (dns.exception.FormError, dns.exception.DNSException, OSError):
            return None
        return self._flatten(zobj, zone, max_records)

    def _flatten(self, zobj: dns.zone.Zone, zone: str, max_records: int) -> list[str]:
        records: list[str] = []
        for name, node in zobj.nodes.items():
            label = name.to_text()
            fqdn = zone if label == "@" else f"{label}.{zone}"
            for rdataset in node.rdatasets:
                records.append(f"{fqdn} {rdataset.to_text()}")
                if len(records) >= max_records:
                    return records
        return records

    def _any(self, ns_ip: str, zone: str, timeout: float) -> list[str]:
        response = self.ctx.dns.raw_query(zone, "ANY", ns_ip, timeout=timeout)
        if response is None or not response.answer:
            return []
        is_rfc8482 = any(
            rrset.rdtype == dns.rdatatype.HINFO and any("RFC8482" in rdata.to_text() for rdata in rrset)
            for rrset in response.answer
        )
        if is_rfc8482:
            return []
        return [rrset.to_text() for rrset in response.answer]


class DanglingCheck(Check):
    module = MODULE
    name = "dangling"
    description = "Dangling CNAME, NS delegation, MX and SRV subdomain takeover detection"
    passive = False

    def run(self) -> dict[str, Any]:
        if self.ctx.target.is_ip:
            self.fail("dangling DNS checks require a domain target")
            return {}
        signature = load_signature("takeover_fingerprints", "cname_services.json")
        services = signature["services"]
        host = self.ctx.target.host
        labels = signature["common_labels"] if self.option("extra_labels", True) else []
        candidates = dedupe(
            [host, f"www.{host}", f"mail.{host}", f"dev.{host}", f"staging.{host}", f"api.{host}"]
            + [f"{label}.{host}" for label in labels]
        )
        max_hosts = int(self.option("max_hosts", 60))
        candidates = candidates[:max_hosts]
        dangling: list[dict[str, Any]] = []
        for sub in candidates:
            result = self._check_cname(sub, services)
            if result:
                dangling.append(result)
        wildcard = self._check_wildcard(services) if int(self.option("wildcard_probes", 3)) > 0 else None
        if wildcard:
            dangling.append(wildcard)
        ns_findings = self._check_ns_delegation() if self.option("check_ns_root", True) else []
        mx_findings = self._check_mx() if self.option("check_mx", True) else []
        srv_findings = self._check_srv() if self.option("check_srv", True) else []
        expired_findings = self._check_expired_targets(candidates) if self.option("check_expired_targets", True) else []
        self._report(dangling, ns_findings, mx_findings, srv_findings)
        for item in expired_findings:
            self.add(
                "DANGLE-CNAME-EXPIRED-DOMAIN",
                f"CNAME on {item['subdomain']} points to an unregistered domain",
                "high",
                f"{item['subdomain']} is an alias of {item['cname']}, whose registered domain {item['root_domain']} does not exist. Anyone can register it and serve content on this subdomain.",
                item,
                confidence="high",
            )
        return {
            "candidates_checked": len(candidates),
            "dangling": dangling,
            "ns_delegation": ns_findings,
            "mx": mx_findings,
            "srv": srv_findings,
            "expired_domains": expired_findings,
        }

    def _report(
        self,
        dangling: list[dict[str, Any]],
        ns_findings: list[dict[str, Any]],
        mx_findings: list[dict[str, Any]],
        srv_findings: list[dict[str, Any]],
    ) -> None:
        for item in dangling:
            reason = item.get("reason", "")
            if reason == "wildcard_active" and item.get("service") != "Unknown":
                self.add(
                    "DANGLE-WILDCARD-TAKEOVER",
                    f"Wildcard CNAME points to a takeover-prone service ({item['service']})",
                    "high",
                    f"Every subdomain of {item['subdomain'].lstrip('*.')} is aliased to {item['cname']} ({item['service']}). If the target account is unclaimed, any hostname can be taken over.",
                    item,
                    confidence=item.get("confidence"),
                )
                continue
            if reason == "fingerprint_match":
                severity = "critical"
            elif reason.startswith("http_"):
                severity = "high"
            elif reason == "wildcard_active":
                severity = "medium"
            else:
                severity = "medium"
            self.add(
                "DANGLE-CNAME",
                f"Dangling CNAME on {item['subdomain']}",
                severity,
                f"{item['subdomain']} points to {item['cname']} ({item['service']}), which appears unclaimed and could allow a subdomain takeover.",
                item,
            )
        for item in ns_findings:
            self.add(
                "DANGLE-NS-DELEGATION",
                "NS delegation points to an unregistered domain",
                "critical",
                f"Nameserver {item['ns']} is delegated from root domain {item['root_domain']}, which appears unregistered, allowing full DNS takeover of this zone.",
                item,
            )
        for item in mx_findings:
            self.add(
                "DANGLE-MX",
                "MX record does not resolve",
                "high",
                f"Mail exchanger {item['mx_host']} does not resolve, which can allow interception of mail sent to this domain by registering the dangling hostname.",
                item,
            )
        for item in srv_findings:
            self.add(
                "DANGLE-SRV",
                "SRV target is unreachable",
                "medium",
                f"{item['srv']} points to {item['target']}:{item['port']}, which does not resolve or is not reachable.",
                item,
            )

    def _resolve_service(self, target: str, services: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        low = target.lower()
        for service in services:
            if any(pattern in low for pattern in service["cname"]):
                return service
        return None

    def _check_cname(self, sub: str, services: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        chain = self.ctx.dns.cname_chain(sub, limit=4)
        if not chain:
            return None
        target = chain[-1]
        service = self._resolve_service(target, services)
        if not service:
            return None
        if not self.ctx.may_contact(sub):
            return None
        return self._liveness(sub, target, service)

    def _liveness(self, sub: str, target: str, service: dict[str, Any]) -> Optional[dict[str, Any]]:
        resolves = bool(self.ctx.dns.resolve_ips(target))
        body, status = "", 0
        if self.option("http_fetch", True):
            for scheme in ("https", "http"):
                response = self.ctx.http.get(f"{scheme}://{sub}/", max_body=65536)
                if response.status:
                    body, status = response.text, response.status
                    break
        for fingerprint in service.get("fingerprints", []):
            if fingerprint and fingerprint in body:
                return {"subdomain": sub, "cname": target, "service": service["name"], "reason": "fingerprint_match", "confidence": "high"}
        if not resolves:
            if status in (404, 400):
                return {"subdomain": sub, "cname": target, "service": service["name"], "reason": f"http_{status}", "confidence": service.get("confidence", "medium")}
            return {"subdomain": sub, "cname": target, "service": service["name"], "reason": "no_response", "confidence": service.get("confidence", "low")}
        return None

    def _check_wildcard(self, services: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        probes = int(self.option("wildcard_probes", 3))
        host = self.ctx.target.host
        hits = 0
        last_target: Optional[str] = None
        for _ in range(probes):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
            sub = f"{label}.{host}"
            chain = self.ctx.dns.cname_chain(sub, limit=4)
            if chain:
                hits += 1
                last_target = chain[-1]
        if hits < max(2, probes - 1) or not last_target:
            return None
        service = self._resolve_service(last_target, services)
        service_name = service["name"] if service else "Unknown"
        return {"subdomain": f"*.{host}", "cname": last_target, "service": service_name, "reason": "wildcard_active", "confidence": "medium"}

    def _check_ns_delegation(self) -> list[dict[str, Any]]:
        basic = get_basic(self.ctx)
        findings: list[dict[str, Any]] = []
        seen_roots: set[str] = set()
        for ns in basic["ns"]:
            labels = ns.split(".")
            if len(labels) < 2:
                continue
            root = ".".join(labels[-2:])
            if root in seen_roots:
                continue
            seen_roots.add(root)
            state = registration_state(self.ctx, root)
            if state is False:
                findings.append({"ns": ns, "root_domain": root})
        return findings

    def _check_expired_targets(self, candidates: list[str]) -> list[dict[str, Any]]:
        own = self.ctx.target.registered_domain
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for sub in candidates:
            chain = self.ctx.dns.cname_chain(sub, limit=4)
            if not chain:
                continue
            target = chain[-1]
            root = registered_domain(target)
            if root == own or root in seen:
                continue
            seen.add(root)
            if self.ctx.dns.resolve_ips(target):
                continue
            if registration_state(self.ctx, root) is False:
                findings.append({"subdomain": sub, "cname": target, "root_domain": root})
        return findings

    def _check_mx(self) -> list[dict[str, Any]]:
        basic = get_basic(self.ctx)
        findings: list[dict[str, Any]] = []
        for host in basic["mx_hosts"]:
            if host and not self.ctx.dns.resolve_ips(host):
                findings.append({"mx_host": host})
        return findings

    def _check_srv(self) -> list[dict[str, Any]]:
        signature = load_signature("dns", "record_types.json")
        prefixes = signature["srv_prefixes"]
        zone = get_basic(self.ctx)["zone"] or self.ctx.target.host
        findings: list[dict[str, Any]] = []
        for prefix in prefixes:
            answer = self.ctx.dns.resolve(f"{prefix}.{zone}", "SRV")
            if not answer.ok:
                continue
            for rdata in answer.rdata:
                target = str(rdata.target).rstrip(".").lower()
                port = rdata.port
                if not target:
                    continue
                if not self.ctx.dns.resolve_ips(target):
                    findings.append({"srv": f"{prefix}.{zone}", "target": target, "port": port, "reason": "unresolvable_target"})
                elif self.ctx.may_contact(target) and not self.ctx.http.tcp_probe(target, port):
                    findings.append({"srv": f"{prefix}.{zone}", "target": target, "port": port, "reason": "port_unreachable"})
        return findings