from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from core.context import ScanContext
from core.modules import Check
from core.utils import (
    as_list,
    dedupe,
    first,
    flatten_vcard,
    is_private_ip,
    load_signature,
    parse_asn,
    reverse_pointer,
)
from modules.whois_dns.records import get_addresses, get_basic

MODULE = "whois_dns"
IP_API = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,countryCode,region,regionName,"
    "city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
)
IPWHO = "https://ipwho.is/{ip}"
RDAP_IP = "https://rdap.org/ip/{ip}"


class ReverseDnsCheck(Check):
    module = MODULE
    name = "reverse_dns"
    description = "PTR lookups, forward confirmation and hostname leakage analysis"
    passive = True

    def run(self) -> dict[str, Any]:
        ips = get_addresses(self.ctx)[: int(self.option("max_ips", 8))]
        if not ips:
            self.fail("no IP addresses available for reverse lookup")
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(ips)))) as pool:
            entries = list(pool.map(self._lookup, ips))
        data = {entry["ip"]: entry for entry in entries}
        for entry in entries:
            self._analyze(entry)
        names = dedupe(
            name
            for entry in entries
            for name in entry["ptr"]
        )
        related_ips = dedupe(
            address
            for entry in entries
            for address in entry["forward_ips"]
        )
        return {
            "target": self.ctx.target.host,
            "target_type": self.ctx.target.kind,
            "ips": ips,
            "dns_names": names,
            "related_ips": related_ips,
            "entries": data,
        }

    def _lookup(self, ip: str) -> dict[str, Any]:
        pointer = reverse_pointer(ip)
        entry: dict[str, Any] = {
            "ip": ip,
            "ptr": [],
            "forward_ips": [],
            "forward_confirmed": None,
            "private": is_private_ip(ip),
        }
        if not pointer:
            return entry
        answer = self.ctx.dns.resolve(pointer, "PTR")
        entry["ptr"] = [r.rstrip(".").lower() for r in answer.records]
        if entry["ptr"]:
            confirmed = False
            for name in entry["ptr"][: int(self.option("max_names", 8))]:
                addresses = self.ctx.dns.resolve_ips(name)
                entry["forward_ips"] = dedupe(entry["forward_ips"] + addresses)
                if ip in addresses:
                    confirmed = True
            entry["forward_confirmed"] = confirmed
        return entry

    def _analyze(self, entry: dict[str, Any]) -> None:
        if entry["private"]:
            self.add(
                "RDNS-PRIVATE-IP",
                "Private or reserved IP address published in DNS",
                "medium",
                "A non-routable address in public DNS discloses internal addressing.",
                {"ip": entry["ip"]},
            )
        if not entry["ptr"] and not entry["private"]:
            self.add(
                "RDNS-MISSING",
                "No PTR record for address",
                "info",
                "The address has no reverse DNS entry, which hurts mail deliverability and makes the host harder to attribute.",
                {"ip": entry["ip"]},
            )
        generic = {
            name: re.compile(pattern, re.I)
            for name, pattern in load_signature("dns", "hosting_providers.json")["generic_ptr_patterns"].items()
        }
        for ptr in entry["ptr"]:
            kinds = [name for name, regex in generic.items() if regex.search(ptr)]
            if kinds:
                self.add(
                    "RDNS-GENERIC-ISP-NAME",
                    "PTR uses a generic provider-assigned name",
                    "info",
                    "The reverse hostname is an automatically generated provider name, which indicates the address has no dedicated identity and is often treated as lower reputation by mail filters.",
                    {"ip": entry["ip"], "ptr": ptr, "patterns": kinds},
                )
        patterns = {
            name: re.compile(pattern, re.I)
            for name, pattern in load_signature("dns", "record_types.json")["ptr_leak_patterns"].items()
        }
        for ptr in entry["ptr"]:
            reasons = [name for name, regex in patterns.items() if regex.search(ptr)]
            if not reasons:
                continue
            severity = "medium" if "internal" in reasons else "low"
            self.add(
                "RDNS-PTR-LEAK",
                "PTR record leaks naming conventions",
                severity,
                "The reverse hostname reveals internal naming, environment or datacenter details.",
                {"ip": entry["ip"], "ptr": ptr, "patterns": reasons},
            )
        if entry["ptr"] and entry["forward_confirmed"] is False:
            self.add(
                "RDNS-FCRDNS-MISMATCH",
                "PTR does not forward-confirm",
                "info",
                "The PTR hostname does not resolve back to the same address.",
                {"ip": entry["ip"], "ptr": entry["ptr"]},
            )


class IpIntelCheck(Check):
    module = MODULE
    name = "ip_intel"
    description = "ASN, geolocation, hosting classification and RDAP network data"
    passive = True

    def run(self) -> dict[str, Any]:
        ips = get_addresses(self.ctx)[: int(self.option("max_ips", 6))]
        if not ips:
            self.fail("no IP addresses available for intelligence lookup")
        with ThreadPoolExecutor(max_workers=min(4, max(1, len(ips)))) as pool:
            records = list(pool.map(self._lookup, ips))
        self.ctx.share("whois_dns.ip_info", records)
        countries = sorted({r["country_code"] for r in records if r.get("country_code")})
        asns = sorted({r["asn"] for r in records if r.get("asn")})
        if len(countries) > 1:
            self.add("IP-MULTI-COUNTRY", "Addresses resolve to multiple countries", "info", "The target is served from several countries.", {"countries": countries})
        self._provider_findings(records, asns)
        for record in records:
            if record.get("proxy_or_vpn"):
                self.add("IP-PROXY-FLAGGED", "Address flagged as proxy or VPN", "info", "The provider classifies this address as proxy, VPN or anonymizer infrastructure.", {"ip": record["ip"]})
        return {"records": records, "countries": countries, "asns": asns}

    def _provider_findings(self, records: list[dict[str, Any]], asns: list[int]) -> None:
        hints = load_signature("dns", "hosting_providers.json")["commodity_hosting_hints"]
        for record in records:
            blob = " ".join(str(record.get(k, "")).lower() for k in ("isp", "org", "as_name") if record.get(k))
            matched = [hint for hint in hints if hint in blob]
            if matched:
                self.add(
                    "IP-ASN-HOSTING-CHEAP",
                    "Address is hosted on a commodity hosting provider",
                    "low",
                    "The address belongs to a low-cost shared or VPS hosting network. These ranges are frequently shared with unrelated and abusive tenants, which affects reputation and isolation.",
                    {"ip": record["ip"], "asn": record.get("asn"), "provider": record.get("as_name") or record.get("org"), "matched": matched},
                    confidence="medium",
                )
        if len(asns) < 2:
            return
        cdn_asns = {int(k) for k in load_signature("dns", "cdn_ns_asn_hints.json")["cdn_asns"]}
        edge = [a for a in asns if a in cdn_asns]
        origin = [a for a in asns if a not in cdn_asns]
        mixed = bool(edge) and bool(origin)
        self.add(
            "DNS-A-MULTI-PROVIDER",
            "Addresses are spread across multiple networks",
            "low" if mixed else "info",
            "Addresses of one host belong to different autonomous systems. When edge and non-edge networks are mixed, the non-edge address is likely the origin server that bypasses CDN or WAF protection."
            if mixed
            else "Addresses of one host belong to different autonomous systems.",
            {"asns": asns, "edge_asns": edge, "other_asns": origin, "mixed_edge_and_origin": mixed},
            confidence="medium" if mixed else "high",
        )

    def _lookup(self, ip: str) -> dict[str, Any]:
        info: dict[str, Any] = {
            "ip": ip, "asn": None, "as_name": None, "org": None, "isp": None, "country": None,
            "country_code": None, "city": None, "region": None, "lat": None, "lon": None,
            "timezone": None, "hosting": None, "proxy_or_vpn": None, "mobile": None,
            "usage_type": "unknown", "cidr": None, "rdap_range": None, "rdap_country": None,
            "rdap_remarks": [], "sources": [], "private": False,
        }
        if is_private_ip(ip):
            info["private"] = True
            info["usage_type"] = "private / reserved"
            return info
        providers = as_list(self.option("providers", ["ip-api", "ipwho", "rdap"]))
        quoted = urllib.parse.quote(ip)
        if "ip-api" in providers:
            self._ip_api(info, quoted)
        if "ipwho" in providers and (info["asn"] is None or info["city"] is None):
            self._ipwho(info, quoted)
        if "rdap" in providers:
            self._rdap(info, quoted)
        info["usage_type"] = self._usage(info)
        return info

    def _ip_api(self, info: dict[str, Any], ip: str) -> None:
        data = self.ctx.http.get_json(IP_API.format(ip=ip))
        if not (isinstance(data, dict) and data.get("status") == "success"):
            return
        info["sources"].append("ip-api")
        asn, as_name = parse_asn(data.get("as"))
        info.update({
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "city": data.get("city"),
            "region": data.get("regionName"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": asn,
            "as_name": first(data.get("asname"), as_name),
            "hosting": bool(data.get("hosting")),
            "proxy_or_vpn": bool(data.get("proxy")),
            "mobile": bool(data.get("mobile")),
        })

    def _ipwho(self, info: dict[str, Any], ip: str) -> None:
        data = self.ctx.http.get_json(IPWHO.format(ip=ip))
        if not (isinstance(data, dict) and data.get("success") is not False):
            return
        info["sources"].append("ipwho.is")
        connection = data.get("connection") or {}
        zone = data.get("timezone")
        for key, value in (
            ("country", data.get("country")),
            ("country_code", data.get("country_code")),
            ("city", data.get("city")),
            ("region", data.get("region")),
            ("lat", data.get("latitude")),
            ("lon", data.get("longitude")),
            ("timezone", zone.get("id") if isinstance(zone, dict) else zone),
            ("isp", first(connection.get("isp"), data.get("isp"))),
            ("org", first(connection.get("org"), data.get("org"))),
            ("asn", connection.get("asn")),
            ("as_name", connection.get("org")),
        ):
            if info.get(key) is None and value is not None:
                info[key] = value

    def _rdap(self, info: dict[str, Any], ip: str) -> None:
        data = self.ctx.http.get_json(RDAP_IP.format(ip=ip))
        if not isinstance(data, dict):
            return
        info["sources"].append("rdap")
        info["rdap_country"] = data.get("country")
        for cidr in data.get("cidr0_cidrs") or []:
            prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
            if prefix and not info["cidr"]:
                info["cidr"] = f"{prefix}/{cidr.get('length')}"
        if data.get("startAddress") and data.get("endAddress"):
            info["rdap_range"] = f"{data['startAddress']} - {data['endAddress']}"
        for entity in data.get("entities") or []:
            card = flatten_vcard(entity.get("vcardArray"))
            roles = [str(r).lower() for r in entity.get("roles") or []]
            if "registrant" in roles or not info["org"]:
                info["org"] = first(info["org"], card.get("organization"), card.get("name"))
        remarks: list[str] = []
        for remark in data.get("remarks") or []:
            remarks.extend(remark.get("description") or [])
        info["rdap_remarks"] = remarks[:3]

    def _usage(self, info: dict[str, Any]) -> str:
        hints = load_signature("dns", "cdn_ns_asn_hints.json")["hosting_hints"]
        blob = " ".join(str(info[k]).lower() for k in ("isp", "org", "as_name") if info.get(k))
        hint_match = any(h in blob for h in hints)
        if info.get("mobile"):
            usage = "mobile"
        elif info.get("hosting") is True or hint_match:
            usage = "datacenter / hosting"
            info["hosting"] = True
        elif info.get("hosting") is False:
            usage = "residential / isp"
        elif info.get("isp"):
            usage = "likely residential / isp"
        else:
            usage = "unknown"
        if info.get("proxy_or_vpn"):
            usage += " (proxy/vpn flagged)"
        return usage

class CdnCheck(Check):
    module = MODULE
    name = "cdn"
    description = "CDN, WAF and anycast infrastructure detection via NS, ASN and HTTP header signatures"
    passive = True

    def run(self) -> dict[str, Any]:
        hints = load_signature("dns", "cdn_ns_asn_hints.json")
        ns_hints = hints["ns_hints"]
        cdn_asns = {int(k): v for k, v in hints["cdn_asns"].items()}
        anycast_asns = {int(v) for v in hints["anycast_asns"]}
        hits: dict[str, list[str]] = {}
        delegation_vendors: set[str] = set()
        edge_vendors: set[str] = set()

        def add_hit(vendor: str, why: str, edge: bool = True) -> None:
            bucket = hits.setdefault(vendor, [])
            if why not in bucket:
                bucket.append(why)
            (edge_vendors if edge else delegation_vendors).add(vendor)

        if not self.ctx.target.is_ip:
            basic = get_basic(self.ctx)
            for ns in basic["ns"]:
                low = ns.lower()
                for vendor, keys in ns_hints.items():
                    if any(k in low for k in keys):
                        add_hit(vendor, f"NS {ns}", edge=False)
            for cname in basic["cname"]:
                low = cname.lower()
                for vendor, keys in ns_hints.items():
                    if any(k in low for k in keys):
                        add_hit(vendor, f"CNAME {cname}")

        anycast = False
        ip_records = self.ctx.recall("whois_dns.ip_info") or []
        for record in ip_records:
            asn = record.get("asn")
            if asn in cdn_asns:
                add_hit(cdn_asns[asn], f"AS{asn} {record.get('as_name') or ''}".strip())
            if asn in anycast_asns:
                anycast = True
            blob = " ".join(str(record.get(k, "")).lower() for k in ("org", "isp", "as_name") if record.get(k))
            for vendor, keys in ns_hints.items():
                if any(k in blob for k in keys):
                    add_hit(vendor, f"IP org/ISP match on {record.get('ip')}")

        waf_detected: list[str] = []
        http_probes: list[dict[str, Any]] = []
        if self.option("http_probe", True) and not self.ctx.target.is_ip and self.ctx.may_contact(self.ctx.target.host):
            header_sig = load_signature("waf_signatures", "cdn_headers.json")
            for scheme in ("https", "http"):
                url = f"{scheme}://{self.ctx.target.host}/"
                response = self.ctx.http.probe_headers(url)
                http_probes.append({"url": url, "status": response.status})
                if not response.status:
                    continue
                headers = response.headers
                for key, vendor in header_sig["headers"].items():
                    if key in headers:
                        add_hit(vendor, f"HTTP header {key}")
                        if vendor in header_sig.get("waf_vendors", []):
                            waf_detected.append(vendor)
                for key in header_sig.get("value_headers", []):
                    if key not in headers:
                        continue
                    value = headers[key].lower()
                    for hint, vendor in header_sig.get("value_hints", []):
                        if hint in value:
                            add_hit(vendor, f"HTTP {key}: {value[:60]}")
                for rule in header_sig.get("value_regex", []):
                    value = headers.get(rule["header"], "")
                    if value and re.search(rule["pattern"], value, re.I):
                        add_hit(rule["vendor"], f"HTTP {rule['header']} pattern match")
                server = headers.get("server", "").lower()
                for hint, vendor in header_sig.get("server_hints", {}).items():
                    if hint in server:
                        add_hit(vendor, f"Server header: {server[:80]}")
                if "cf-ray" in headers and response.status in header_sig.get("challenge_statuses", []):
                    if "Cloudflare WAF" not in waf_detected:
                        waf_detected.append("Cloudflare WAF")
                    break

        confirmed = sorted(edge_vendors)
        delegation_only = sorted(delegation_vendors - edge_vendors)
        http_verified = any(probe.get("status") for probe in http_probes)
        asns = [record.get("asn") for record in ip_records if record.get("asn")]
        outside_edge = bool(ip_records) and len(asns) == len(ip_records) and not any(asn in cdn_asns for asn in asns)
        origin_exposed = bool(delegation_only) and outside_edge

        data = {
            "behind_cdn": bool(confirmed),
            "vendors": sorted(hits.keys()),
            "confirmed_vendors": confirmed,
            "dns_only_vendors": delegation_only,
            "origin_exposed": origin_exposed,
            "evidence": hits,
            "waf_detected": dedupe(waf_detected),
            "anycast": anycast,
            "http_probes": http_probes,
        }
        if confirmed:
            self.add(
                "CDN-DETECTED",
                f"Traffic is served through {', '.join(confirmed)}",
                "info",
                "The target is fronted by a CDN or reverse proxy, which can mask the true origin server address.",
                {"vendors": confirmed, "dns_only_vendors": delegation_only},
                confidence="high",
            )
        elif delegation_only:
            self.add(
                "CDN-DETECTED",
                f"{', '.join(delegation_only)} detected through DNS delegation only",
                "info",
                "DNS records point to the vendor, but no edge evidence was observed in the resolved addresses or HTTP responses.",
                {"vendors": delegation_only},
                confidence="low" if origin_exposed else "medium",
            )
        if origin_exposed:
            self.add(
                "CDN-ORIGIN-EXPOSED",
                f"Origin appears directly reachable despite {', '.join(delegation_only)} DNS",
                "low",
                "DNS is delegated to the vendor, but the resolved addresses are outside any CDN network and no edge headers were returned. The origin address is public and CDN or WAF protection is likely not applied.",
                {
                    "vendors": delegation_only,
                    "ips": [record.get("ip") for record in ip_records],
                    "asns": sorted(set(asns)),
                    "hosting": sorted({str(record.get("as_name") or record.get("org")) for record in ip_records if record.get("as_name") or record.get("org")}),
                    "http_verified": http_verified,
                },
                confidence="high" if http_verified else "medium",
            )
        if data["waf_detected"]:
            self.add(
                "WAF-DETECTED",
                f"Web application firewall detected: {', '.join(data['waf_detected'])}",
                "info",
                "A web application firewall was identified from response headers or challenge behavior.",
                {"waf": data["waf_detected"]},
                confidence="high",
            )
        return data