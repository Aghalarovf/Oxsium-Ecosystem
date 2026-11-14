from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import dns.rdatatype

from core.context import ScanContext
from core.modules import Check
from core.utils import load_signature
from modules.whois_dns.records import get_basic

MODULE = "whois_dns"


class DnssecCheck(Check):
    module = MODULE
    name = "dnssec"
    description = "DNSSEC chain validation, algorithm strength, NSEC walking, SSHFP and TLSA/DANE analysis"
    passive = True
    domain_only = True

    def run(self) -> dict[str, Any]:
        host = self.ctx.target.host
        zone = get_basic(self.ctx)["zone"] or host
        data: dict[str, Any] = {
            "zone": zone,
            "dnskey": self._dnskeys(zone),
            "ds": self._ds(zone),
            "rrsig": self._rrsig_expiry(zone),
            "nsec": self._nsec(zone),
            "sshfp": self._sshfp(host),
            "tlsa": self._tlsa(host),
        }
        self._analyze_chain(data)
        return data

    def _dnskeys(self, zone: str) -> list[dict[str, Any]]:
        catalog = load_signature("dns", "record_types.json")["dnskey_algorithms"]
        answer = self.ctx.dns.resolve(zone, "DNSKEY")
        keys: list[dict[str, Any]] = []
        for rdata in answer.rdata:
            info = catalog.get(str(rdata.algorithm), {"name": str(rdata.algorithm), "status": "unknown"})
            keys.append({
                "flags": rdata.flags,
                "is_ksk": bool(rdata.flags & 0x0001),
                "algorithm": rdata.algorithm,
                "algorithm_name": info["name"],
                "algorithm_status": info["status"],
            })
        weak = [k for k in keys if k["algorithm_status"] in ("weak", "deprecated")]
        if weak:
            severity = "high" if len(weak) == len(keys) else "medium"
            self.add(
                "DNSSEC-WEAK-ALGORITHM",
                "DNSKEY uses a weak or deprecated algorithm",
                severity,
                "The zone signs records using an algorithm considered weak or deprecated, which lowers the effort required to forge signatures.",
                {"weak": weak},
            )
        return keys

    def _ds(self, zone: str) -> list[dict[str, Any]]:
        catalog = load_signature("dns", "record_types.json")["ds_digest_types"]
        answer = self.ctx.dns.resolve(zone, "DS")
        entries: list[dict[str, Any]] = []
        for rdata in answer.rdata:
            info = catalog.get(str(rdata.digest_type), {"name": str(rdata.digest_type), "status": "unknown"})
            entries.append({
                "key_tag": rdata.key_tag,
                "algorithm": rdata.algorithm,
                "digest_type": rdata.digest_type,
                "digest_status": info["status"],
            })
        weak = [e for e in entries if e["digest_status"] == "weak"]
        if weak:
            self.add(
                "DNSSEC-WEAK-DS-DIGEST",
                "DS record uses a weak digest algorithm",
                "medium",
                "SHA-1 based DS digests are considered weak; SHA-256 or stronger digests should be published instead.",
                {"entries": weak},
            )
        return entries

    def _rrsig_expiry(self, zone: str) -> list[dict[str, Any]]:
        sigs: list[dict[str, Any]] = []
        if not self.ctx.dns.nameservers:
            return sigs
        response = self.ctx.dns.raw_query(zone, "DNSKEY", self.ctx.dns.nameservers[0], dnssec=True)
        if response is None:
            return sigs
        now = datetime.now(timezone.utc)
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rdata in rrset:
                expires = datetime.fromtimestamp(rdata.expiration, tz=timezone.utc)
                days_left = (expires - now).days
                entry = {
                    "type_covered": dns.rdatatype.to_text(rdata.type_covered),
                    "expires": expires.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_left": days_left,
                }
                sigs.append(entry)
                if days_left < 0:
                    self.add(
                        "DNSSEC-RRSIG-EXPIRED",
                        f"RRSIG for {entry['type_covered']} has expired",
                        "critical",
                        f"The signature expired on {entry['expires']}; validating resolvers will reject answers for this type.",
                        entry,
                    )
                elif days_left < 3:
                    self.add(
                        "DNSSEC-RRSIG-EXPIRING",
                        f"RRSIG for {entry['type_covered']} expires within 3 days",
                        "high",
                        f"The signature expires on {entry['expires']}.",
                        entry,
                    )
                elif days_left < 7:
                    self.add(
                        "DNSSEC-RRSIG-EXPIRING",
                        f"RRSIG for {entry['type_covered']} expires within 7 days",
                        "medium",
                        f"The signature expires on {entry['expires']}.",
                        entry,
                    )
        return sigs

    def _nsec(self, zone: str) -> dict[str, Any]:
        info: dict[str, Any] = {"type": None, "walked": [], "opt_out": None, "iterations": None}
        nsec3param = self.ctx.dns.resolve(zone, "NSEC3PARAM")
        if nsec3param.ok and nsec3param.rdata:
            rdata = nsec3param.rdata[0]
            info["type"] = "NSEC3"
            info["opt_out"] = bool(rdata.flags & 0x01)
            info["iterations"] = rdata.iterations
            if info["opt_out"]:
                self.add(
                    "DNSSEC-NSEC3-OPTOUT",
                    "NSEC3 opt-out is enabled",
                    "low",
                    "Opt-out NSEC3 excludes unsigned delegations from the authenticated denial of existence chain.",
                    info,
                )
            if rdata.iterations > 0:
                severity = "medium" if rdata.iterations > 100 else "low"
                self.add(
                    "DNSSEC-NSEC3-ITERATIONS",
                    f"NSEC3 uses {rdata.iterations} iterations",
                    severity,
                    "RFC 9276 recommends zero NSEC3 iterations; higher values add resolver computation load without a meaningful security benefit.",
                    info,
                )
            return info
        nsec = self.ctx.dns.resolve(zone, "NSEC")
        if nsec.ok:
            info["type"] = "NSEC"
            if self.option("nsec_walk", True):
                info["walked"] = self._walk(zone)
                if info["walked"]:
                    self.add(
                        "DNSSEC-NSEC-ZONEWALK",
                        "NSEC zone walking enumerated zone contents",
                        "medium",
                        f"Walking the NSEC chain revealed {len(info['walked'])} owner name(s), allowing enumeration of the zone contents without a zone transfer.",
                        {"names": info["walked"][:50]},
                    )
        return info

    def _walk(self, zone: str) -> list[str]:
        limit = int(self.option("nsec_walk_limit", 50))
        discovered: list[str] = []
        current = zone
        seen: set[str] = set()
        while len(discovered) < limit and current not in seen:
            seen.add(current)
            answer = self.ctx.dns.resolve(current, "NSEC")
            if not answer.ok or not answer.rdata:
                break
            next_name = str(answer.rdata[0].next).rstrip(".").lower()
            discovered.append(current)
            if next_name == zone or next_name in seen:
                break
            current = next_name
        return discovered

    def _sshfp(self, host: str) -> list[dict[str, Any]]:
        catalog = load_signature("dns", "record_types.json")
        algos = catalog["sshfp_algorithms"]
        fingerprint_types = catalog["sshfp_fingerprint_types"]
        answer = self.ctx.dns.resolve(host, "SSHFP")
        entries: list[dict[str, Any]] = []
        for rdata in answer.rdata:
            entry = {
                "algorithm": algos.get(str(rdata.algorithm), str(rdata.algorithm)),
                "fingerprint_type": fingerprint_types.get(str(rdata.fp_type), str(rdata.fp_type)),
                "fingerprint": rdata.fingerprint.hex(),
            }
            entries.append(entry)
            if rdata.fp_type == 1:
                self.add(
                    "DNSSEC-SSHFP-WEAK-HASH",
                    "SSHFP record uses a SHA-1 fingerprint",
                    "low",
                    "SHA-256 fingerprints are recommended over the weaker SHA-1 fingerprint type.",
                    entry,
                )
        return entries

    def _tlsa(self, host: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for item in load_signature("dns", "record_types.json")["tlsa_prefixes"]:
            name = f"{item['prefix']}.{host}"
            answer = self.ctx.dns.resolve(name, "TLSA")
            for rdata in answer.rdata:
                entries.append({
                    "name": name,
                    "service": item["service"],
                    "usage": rdata.usage,
                    "selector": rdata.selector,
                    "matching_type": rdata.mtype,
                    "cert_hash": rdata.cert.hex(),
                })
        return entries

    def _analyze_chain(self, data: dict[str, Any]) -> None:
        has_dnskey = bool(data["dnskey"])
        has_ds = bool(data["ds"])
        has_rrsig = bool(data["rrsig"])
        chain_valid = has_dnskey and has_ds and has_rrsig
        data["chain_valid"] = chain_valid
        if has_dnskey and not has_ds:
            self.add(
                "DNSSEC-UNSIGNED-DELEGATION",
                "DNSKEY present but no DS record at the parent",
                "medium",
                "The zone is signed but the parent zone does not delegate a chain of trust, so validating resolvers will treat it as insecure.",
                {"zone": data["zone"]},
            )
        elif not has_dnskey:
            self.add(
                "DNSSEC-NOT-ENABLED",
                "DNSSEC is not enabled",
                "low",
                "No DNSKEY record was found for this zone, so responses cannot be cryptographically validated.",
                {"zone": data["zone"]},
            )
        if data["sshfp"] and not chain_valid:
            self.add(
                "DNSSEC-SSHFP-UNVALIDATED",
                "SSHFP records exist without a valid DNSSEC chain",
                "high",
                "Without DNSSEC validation, published SSHFP records cannot be trusted and provide no protection against SSH man-in-the-middle attacks via DNS spoofing.",
                {"zone": data["zone"]},
            )
        if data["tlsa"] and not chain_valid:
            self.add(
                "DNSSEC-TLSA-UNVALIDATED",
                "TLSA records exist without a valid DNSSEC chain",
                "high",
                "Without DNSSEC validation, published TLSA/DANE records cannot be trusted to pin certificates, undermining the protection they are meant to provide.",
                {"zone": data["zone"]},
            )