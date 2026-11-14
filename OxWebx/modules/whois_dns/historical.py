from __future__ import annotations

import re
import urllib.parse
from typing import Any, Optional

from core.context import ScanContext
from core.modules import Check
from core.utils import as_list, days_since, dedupe, first, parse_dt
from modules.whois_dns.records import get_addresses, get_basic
from modules.whois_dns.whois import RDAP_DOMAIN

MODULE = "whois_dns"

CDX_FIRST = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&fl=timestamp,statuscode,original"
    "&filter=statuscode:200&limit=1&fastLatest=true"
)
CDX_LATEST = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&fl=timestamp,statuscode,original"
    "&filter=statuscode:200&limit=1&fastLatest=true&sort=reverse"
)
WHOISFREAKS = "https://whoisfreaks.com/v1.0/whois/history?apiKey={key}&whois=live&domainName={domain}"

HT_REVERSE_NS = "https://api.hackertarget.com/reversens/?q={ns}"
HT_REVERSE_IP = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
RIPESTAT_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)
RATE_LIMIT_PATTERNS = ("error: api count exceeded", "error: access denied", "<!doctype", "<html")


def _ts_to_date(timestamp: str) -> Optional[str]:
    if not timestamp or len(timestamp) < 8:
        return None
    return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"


def _cdx_timestamp(raw: Any) -> Optional[str]:
    if not isinstance(raw, list) or len(raw) < 2:
        return None
    row = raw[1]
    if isinstance(row, list) and row:
        return _ts_to_date(str(row[0]))
    return None


def _parse_hackertarget(text: str) -> list[str]:
    low = text.lower()
    if not text or any(pattern in low for pattern in RATE_LIMIT_PATTERNS):
        return []
    domains: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if "," in line:
            line = line.split(",")[-1].strip()
        if DOMAIN_RE.fullmatch(line):
            domains.append(line.lower())
    return domains


class HistoricalCheck(Check):
    module = MODULE
    name = "historical"
    description = "RDAP event history and Wayback Machine archive presence"
    passive = True
    domain_only = True

    def run(self) -> dict[str, Any]:
        domain = self.ctx.target.registered_domain
        encoded = urllib.parse.quote(domain)
        data: dict[str, Any] = {"domain": domain, "rdap_events": [], "archive": None, "snapshots": []}
        if self.option("rdap_events", True):
            self._rdap_events(encoded, data)
        if self.option("wayback", True):
            self._wayback(encoded, data)
        api_key = self.option("whoisfreaks_api_key")
        if api_key:
            self._whoisfreaks(encoded, api_key, data)
        if not data["rdap_events"] and not data["archive"] and not data["snapshots"]:
            self.fail("no historical data retrieved for this domain")
        self._history_findings(data)
        if data["archive"] and data["archive"].get("first_seen"):
            self.add(
                "HISTORY-ARCHIVE-PRESENCE",
                "Domain has historical web archive snapshots",
                "info",
                f"First archived {data['archive']['first_seen']}, most recently {data['archive'].get('last_seen')}.",
                data["archive"],
            )
        return data

    def _history_findings(self, data: dict[str, Any]) -> None:
        domain = data["domain"]
        snapshots = sorted((s for s in data["snapshots"] if isinstance(s, dict)), key=lambda s: s.get("date") or "")
        recent_days = int(self.option("recent_days", 90))
        gap_days = int(self.option("archive_gap_days", 730))
        registrars = []
        for snapshot in snapshots:
            name = (snapshot.get("registrar") or "").strip()
            if name and name.lower() not in [r.lower() for r in registrars]:
                registrars.append(name)
        transfers = [e for e in data["rdap_events"] if "transfer" in e["action"].lower()]
        if len(registrars) > 1 or transfers:
            self.add(
                "HISTORY-REGISTRAR-CHANGE",
                "Registrar change recorded in history",
                "low",
                "The domain moved between registrars. Transfers are normal, but unexpected ones can signal hijacking or a change of ownership.",
                {"domain": domain, "registrars": registrars, "transfer_events": transfers},
                confidence="high" if len(registrars) > 1 else "medium",
            )
        owners = []
        for snapshot in snapshots:
            owner = (snapshot.get("registrant") or "").strip()
            if owner and owner.lower() not in [o.lower() for o in owners]:
                owners.append(owner)
        if len(owners) > 1:
            self.add(
                "HISTORY-OWNER-CHANGE",
                "Registrant change recorded in history",
                "medium",
                "Historical WHOIS snapshots show different registrants, which indicates a transfer of ownership or a reassigned domain.",
                {"domain": domain, "registrants": owners},
            )
        latest_change = None
        for previous, current in zip(snapshots, snapshots[1:]):
            before = sorted(previous.get("name_servers") or [])
            after = sorted(current.get("name_servers") or [])
            if before and after and before != after:
                latest_change = {"from": before, "to": after, "date": current.get("date"), "age_days": days_since(current.get("date"))}
        if latest_change and latest_change["age_days"] is not None and latest_change["age_days"] <= recent_days:
            self.add(
                "HISTORY-NS-CHANGE-RECENT",
                "Nameservers changed recently",
                "medium",
                f"The delegation changed within the last {recent_days} days. Recent nameserver changes precede many hijacking and migration incidents.",
                {"domain": domain, **latest_change},
            )
        archive = data.get("archive") or {}
        idle = days_since(archive.get("last_seen")) if archive.get("last_seen") else None
        if idle is not None and idle > gap_days:
            self.add(
                "HISTORY-ARCHIVE-GAP",
                "No web archive activity for a long period",
                "low",
                "The domain has no archived web content for an extended period, which is typical of parked, abandoned or repurposed domains.",
                {"domain": domain, "last_seen": archive.get("last_seen"), "idle_days": idle, "threshold_days": gap_days},
            )

    def _rdap_events(self, encoded: str, data: dict[str, Any]) -> None:
        rdap = self.ctx.http.get_json(RDAP_DOMAIN.format(domain=encoded))
        if not isinstance(rdap, dict):
            return
        for event in rdap.get("events") or []:
            action = event.get("eventAction", "")
            date = parse_dt(event.get("eventDate", ""))
            if action and date:
                data["rdap_events"].append({"action": action, "date": date})

    def _wayback(self, encoded: str, data: dict[str, Any]) -> None:
        first_raw = self.ctx.http.get_json(CDX_FIRST.format(domain=encoded))
        latest_raw = self.ctx.http.get_json(CDX_LATEST.format(domain=encoded))
        first_seen = _cdx_timestamp(first_raw)
        last_seen = _cdx_timestamp(latest_raw)
        if not (first_seen or last_seen):
            return
        archive: dict[str, Any] = {"first_seen": first_seen, "last_seen": last_seen, "source": "Wayback Machine (CDX)"}
        age = days_since(first_seen)
        if age is not None and age > 0:
            archive["age_days"] = age
        data["archive"] = archive

    def _whoisfreaks(self, encoded: str, api_key: str, data: dict[str, Any]) -> None:
        history = self.ctx.http.get_json(WHOISFREAKS.format(key=urllib.parse.quote(api_key), domain=encoded))
        records = history if isinstance(history, list) else (history or {}).get("whois_records") or []
        for record in records:
            if not isinstance(record, dict):
                continue
            data["snapshots"].append({
                "date": parse_dt(record.get("query_time") or record.get("updated_date", "")),
                "registrar": record.get("registrar_name") or record.get("registrar"),
                "created": parse_dt(record.get("create_date") or record.get("creation_date", "")),
                "expires": parse_dt(record.get("expiry_date") or record.get("expiration_date", "")),
                "name_servers": [n.lower().strip() for n in (record.get("name_servers") or []) if n],
                "registrant": self._registrant(record),
            })

    def _registrant(self, record: dict[str, Any]) -> Optional[str]:
        contact = record.get("registrant_contact")
        if isinstance(contact, dict):
            return first(contact.get("name"), contact.get("company"), contact.get("organization"))
        return first(record.get("registrant_name"), record.get("registrant_organization"))


class CrossSearchCheck(Check):
    module = MODULE
    name = "cross_search"
    description = "Pivoting on nameservers, IPs and ASN to discover related domains and infrastructure"
    passive = True

    def run(self) -> dict[str, Any]:
        domain = self.ctx.target.registered_domain
        sources = as_list(self.option("sources", ["hackertarget", "ripestat"]))
        max_ns = int(self.option("max_ns", 3))
        max_ips = int(self.option("max_ips", 2))
        max_related = int(self.option("max_related", 200))
        nameservers = [] if self.ctx.target.is_ip else get_basic(self.ctx)["ns"][:max_ns]
        ips = get_addresses(self.ctx)[:max_ips]
        related: list[dict[str, Any]] = []
        pivots: list[str] = []
        errors: list[str] = []
        if "hackertarget" in sources:
            self._hackertarget_pivots(nameservers, ips, related, pivots, errors)
        if "ripestat" in sources:
            self._ripestat_pivots(pivots, errors)
        unique = self._dedupe(related, domain, max_related)
        shared_limit = int(self.option("shared_hosting_threshold", 10))
        for ip in ips:
            sharing = dedupe(item["domain"] for item in related if item["pivot"] == "ip" and item["value"] == ip and item["domain"] != domain)
            if len(sharing) >= shared_limit:
                self.add(
                    "IP-SHARED-HOSTING",
                    f"{ip} hosts {len(sharing)} other domains",
                    "low",
                    "Many unrelated domains share this address, so reputation, outages and attacks against neighbors can affect the target.",
                    {"ip": ip, "count": len(sharing), "sample": sharing[:10]},
                )
        if len(unique) > 20:
            self.add(
                "CROSS-SEARCH-WIDE-FOOTPRINT",
                f"{len(unique)} related domains discovered via infrastructure pivoting",
                "info",
                "A large number of domains share nameservers or IP addresses with this target, which may indicate a shared hosting provider or a common owner.",
                {"count": len(unique), "pivots": pivots},
            )
        return {"pivots_used": pivots, "related_domains": unique, "related_count": len(unique), "errors": errors}

    def _hackertarget_pivots(
        self,
        nameservers: list[str],
        ips: list[str],
        related: list[dict[str, Any]],
        pivots: list[str],
        errors: list[str],
    ) -> None:
        if not self.ctx.may_contact("api.hackertarget.com"):
            return
        for ns in nameservers:
            try:
                domains = self._pivot_ns(ns)
                if domains:
                    pivots.append(f"NS:{ns}")
                    related.extend({"domain": d, "pivot": "nameserver", "value": ns, "source": "hackertarget"} for d in domains)
            except Exception as exc:
                errors.append(f"ns-pivot [{ns}]: {exc}")
        for ip in ips:
            try:
                domains = self._pivot_ip(ip)
                if domains:
                    pivots.append(f"IP:{ip}")
                    related.extend({"domain": d, "pivot": "ip", "value": ip, "source": "hackertarget"} for d in domains)
            except Exception as exc:
                errors.append(f"ip-pivot [{ip}]: {exc}")

    def _ripestat_pivots(self, pivots: list[str], errors: list[str]) -> None:
        for record in (self.ctx.recall("whois_dns.ip_info") or [])[:1]:
            asn = record.get("asn")
            if not asn:
                continue
            try:
                data = self.ctx.http.get_json(RIPESTAT_PREFIXES.format(asn=asn))
                if isinstance(data, dict) and data.get("status") == "ok":
                    pivots.append(f"ASN:AS{asn}")
            except Exception as exc:
                errors.append(f"ripestat-asn [{asn}]: {exc}")

    def _pivot_ns(self, ns: str) -> list[str]:
        ns = ns.rstrip(".")
        response = self.ctx.http.get(HT_REVERSE_NS.format(ns=urllib.parse.quote(ns)), max_body=131072)
        return _parse_hackertarget(response.text) if response.status == 200 else []

    def _pivot_ip(self, ip: str) -> list[str]:
        response = self.ctx.http.get(HT_REVERSE_IP.format(ip=urllib.parse.quote(ip)), max_body=131072)
        return _parse_hackertarget(response.text) if response.status == 200 else []

    def _dedupe(self, related: list[dict[str, Any]], domain: str, max_related: int) -> list[dict[str, Any]]:
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for item in related:
            if item["domain"] != domain and item["domain"] not in seen:
                seen.add(item["domain"])
                unique.append(item)
        return unique[:max_related]