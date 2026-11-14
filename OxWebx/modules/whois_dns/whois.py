from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

from core.context import ScanContext
from core.modules import Check
from core.utils import (
    as_list,
    days_since,
    days_until,
    first,
    flatten_vcard,
    load_signature,
    looks_privacy,
    parse_datetime,
    parse_dt,
)
from modules.whois_dns.records import get_basic

MODULE = "whois_dns"
IANA_WHOIS = "whois.iana.org"
RDAP_DOMAIN = "https://rdap.org/domain/{domain}"
ROLES = ("registrant", "admin", "tech", "billing")


@dataclass
class ContactInfo:
    name: str = ""
    organization: str = ""
    address: str = ""
    country: str = ""
    phone: str = ""
    email: str = ""

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.__dict__.items() if v}

    def is_empty(self) -> bool:
        return not any(self.__dict__.values())


@dataclass
class WhoisRecord:
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    days_until_expiry: Optional[int] = None
    status: list[str] = field(default_factory=list)
    registrar: Optional[str] = None
    registrar_iana_id: Optional[str] = None
    whois_server: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    contacts: dict[str, ContactInfo] = field(default_factory=lambda: {r: ContactInfo() for r in ROLES})
    privacy: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    raw: str = ""
    unavailable_reason: Optional[str] = None
    lookup_url: Optional[str] = None

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        data = {
            "created": self.created,
            "updated": self.updated,
            "expires": self.expires,
            "days_until_expiry": self.days_until_expiry,
            "status": self.status,
            "registrar": self.registrar,
            "registrar_iana_id": self.registrar_iana_id,
            "name_servers": self.name_servers,
            "dnssec": self.dnssec,
            "contacts": {r: c.to_dict() for r, c in self.contacts.items()},
            "privacy": self.privacy,
            "sources": self.sources,
            "unavailable_reason": self.unavailable_reason,
            "lookup_url": self.lookup_url,
        }
        if include_raw:
            data["raw"] = self.raw
        return data


def whois_field(raw: str, keys: list[str]) -> list[str]:
    found: list[str] = []
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value or value.lower() in {".", "not disclosed", "n/a", "redacted for privacy"}:
            continue
        for wanted in keys:
            wanted = wanted.lower()
            if key == wanted or key.endswith(" " + wanted):
                if value not in found:
                    found.append(value)
    return found


def whois_block(raw: str, prefix: str) -> ContactInfo:
    mapping = {
        "name": ["name"],
        "organization": ["organization", "organisation", "org"],
        "address": ["street", "address", "address1", "address2"],
        "city": ["city"],
        "state": ["state", "state/province", "province"],
        "postal": ["postal code", "postalcode", "zip"],
        "country": ["country", "country code", "countrycode"],
        "phone": ["phone", "telephone", "phone number"],
        "email": ["email", "e-mail", "mail"],
    }
    out: dict[str, list[str]] = {k: [] for k in mapping}
    prefix = prefix.lower()
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = re.sub(r"\s+", " ", key.strip().lower())
        value = value.strip()
        if not value or not key.startswith(prefix):
            continue
        rest = key[len(prefix):].strip(" :/")
        for dest, aliases in mapping.items():
            if rest in aliases:
                if value not in out[dest]:
                    out[dest].append(value)
                break
    address = ", ".join(
        part
        for part in (
            " ".join(out["address"]),
            ", ".join(out["city"]),
            ", ".join(out["state"]),
            ", ".join(out["postal"]),
        )
        if part
    )
    return ContactInfo(
        name="; ".join(out["name"]),
        organization="; ".join(out["organization"]),
        address=address,
        country="; ".join(out["country"]),
        phone="; ".join(out["phone"]),
        email="; ".join(out["email"]),
    )


def parse_whois_raw(raw: str) -> dict[str, Any]:
    statuses: list[str] = []
    for status in whois_field(raw, ["domain status", "status"]):
        token = status.split()[0] if status else status
        if token and token not in statuses:
            statuses.append(token)
    created = first(*whois_field(raw, ["creation date", "created", "created on", "registered on", "registration time", "registered"]))
    updated = first(*whois_field(raw, ["updated date", "last updated", "last modified", "modified", "changed"]))
    expires = first(*whois_field(raw, ["registry expiry date", "registrar registration expiration date", "expiry date", "expiration date", "expires", "expire", "paid-till"]))
    contacts: dict[str, ContactInfo] = {}
    for role, alt in (("registrant", None), ("admin", "administrative"), ("tech", "technical"), ("billing", None)):
        block = whois_block(raw, role)
        if block.is_empty() and alt:
            block = whois_block(raw, alt)
        contacts[role] = block
    return {
        "created": parse_dt(created),
        "updated": parse_dt(updated),
        "expires": parse_dt(expires),
        "status": statuses,
        "registrar": first(*whois_field(raw, ["registrar", "registrar name", "sponsoring registrar"])),
        "registrar_iana_id": first(*whois_field(raw, ["registrar iana id", "iana id"])),
        "whois_server": first(*whois_field(raw, ["registrar whois server", "whois server", "refer"])),
        "name_servers": [n.split()[0].rstrip(".").lower() for n in whois_field(raw, ["name server", "nserver", "nameserver"])],
        "dnssec": first(*whois_field(raw, ["dnssec"])),
        "contacts": contacts,
        "raw": raw,
    }


def parse_rdap_domain(data: dict[str, Any]) -> dict[str, Any]:
    events: dict[str, Optional[str]] = {}
    for event in data.get("events") or []:
        events[(event.get("eventAction") or "").lower()] = parse_dt(event.get("eventDate"))
    contacts: dict[str, ContactInfo] = {r: ContactInfo() for r in ROLES}
    role_map = {"registrant": "registrant", "administrative": "admin", "admin": "admin", "technical": "tech", "tech": "tech", "billing": "billing"}
    registrar: Optional[str] = None
    iana_id: Optional[str] = None

    def assign(entity: dict[str, Any]) -> None:
        card = flatten_vcard(entity.get("vcardArray"))
        for role in (str(r).lower() for r in entity.get("roles") or []):
            dest = role_map.get(role)
            if dest and card and contacts[dest].is_empty():
                address = card.get("address", "")
                contacts[dest] = ContactInfo(
                    name=card.get("name", ""),
                    organization=card.get("organization", ""),
                    address=address,
                    country=address.split(",")[-1].strip() if address else "",
                    phone=card.get("phone", ""),
                    email=card.get("email", ""),
                )

    for entity in data.get("entities") or []:
        roles = [str(r).lower() for r in entity.get("roles") or []]
        card = flatten_vcard(entity.get("vcardArray"))
        if "registrar" in roles:
            registrar = first(card.get("name"), card.get("organization"), entity.get("handle"))
            for public_id in entity.get("publicIds") or []:
                if str(public_id.get("type", "")).lower() in {"iana registrar id", "iana id"}:
                    iana_id = str(public_id.get("identifier"))
            if not iana_id and str(entity.get("handle", "")).isdigit():
                iana_id = str(entity["handle"])
        assign(entity)
        for sub in entity.get("entities") or []:
            assign(sub)
    nameservers = []
    for item in data.get("nameservers") or []:
        name = item.get("ldhName") or item.get("unicodeName")
        if name:
            nameservers.append(name.rstrip(".").lower())
    dnssec = None
    secure = data.get("secureDNS")
    if isinstance(secure, dict) and "delegationSigned" in secure:
        dnssec = "signedDelegation" if secure.get("delegationSigned") else "unsigned"
    return {
        "created": first(events.get("registration"), events.get("registered")),
        "updated": first(events.get("last changed"), events.get("last update of rdap database")),
        "expires": first(events.get("expiration"), events.get("expiry")),
        "status": as_list(data.get("status")),
        "registrar": registrar,
        "registrar_iana_id": iana_id,
        "name_servers": nameservers,
        "dnssec": dnssec,
        "contacts": contacts,
    }


def merge_record(base: WhoisRecord, patch: dict[str, Any]) -> WhoisRecord:
    for key in ("created", "updated", "expires", "registrar", "registrar_iana_id", "dnssec", "whois_server"):
        if not getattr(base, key) and patch.get(key):
            setattr(base, key, patch[key])
    for status in as_list(patch.get("status")):
        if status not in base.status:
            base.status.append(status)
    for server in as_list(patch.get("name_servers")):
        server = server.rstrip(".").lower()
        if server not in base.name_servers:
            base.name_servers.append(server)
    for role in ROLES:
        incoming = (patch.get("contacts") or {}).get(role)
        if not isinstance(incoming, ContactInfo):
            continue
        existing = base.contacts[role]
        if existing.is_empty():
            base.contacts[role] = incoming
        else:
            for key, value in incoming.__dict__.items():
                if value and not getattr(existing, key):
                    setattr(existing, key, value)
    return base


def detect_privacy(record: WhoisRecord) -> dict[str, Any]:
    signature = load_signature("dns", "privacy_hints.json")
    parts = [record.raw, record.registrar or ""]
    for contact in record.contacts.values():
        parts.extend(str(v) for v in contact.__dict__.values())
    blob = "\n".join(parts).lower()
    active = looks_privacy(blob)
    indicators = [h for h in signature["indicators"] if h in blob] if active else []
    emails = [c.email for c in record.contacts.values() if c.email]
    return {
        "enabled": active,
        "indicators": indicators,
        "visible_emails": emails,
        "note": "WHOIS privacy or redaction appears active" if active else "No privacy or redaction markers found",
    }


def lookup_domain(ctx: ScanContext, domain: str, forced_server: Optional[str] = None) -> WhoisRecord:
    record = WhoisRecord()
    tld = domain.rsplit(".", 1)[-1].lower()
    registry = load_signature("dns", "cctld_whois.json")
    if ctx.option(MODULE, "whois.use_rdap", True):
        data = ctx.http.get_json(RDAP_DOMAIN.format(domain=urllib.parse.quote(domain)))
        if isinstance(data, dict) and (data.get("ldhName") or data.get("objectClassName") == "domain"):
            merge_record(record, parse_rdap_domain(data))
            record.sources.append("rdap")
    if not ctx.option(MODULE, "whois.use_port43", True):
        record.privacy = detect_privacy(record)
        return record
    raw_parts: list[str] = []
    server = forced_server
    registry_answered = False
    if not server:
        iana = ctx.http.tcp_query(IANA_WHOIS, domain)
        if iana:
            registry_answered = True
            answered = first(*whois_field(iana, ["domain"]))
            if not answered or answered.lower().rstrip(".") == domain.lower():
                raw_parts.append(f"; IANA\n{iana}")
            server = first(*whois_field(iana, ["whois", "refer"]))
            remark_urls = re.findall(r"https?://[^\s]+", "\n".join(whois_field(iana, ["remarks"])))
            record.lookup_url = first(registry.get("web_only", {}).get(tld), *remark_urls)
        if not server:
            server = registry.get("servers", {}).get(tld)
    if server:
        raw = ctx.http.tcp_query(server, domain)
        if raw:
            raw_parts.append(f"; {server}\n{raw}")
            parsed = parse_whois_raw(raw)
            merge_record(record, parsed)
            record.sources.append(f"whois:{server}")
            follow = parsed.get("whois_server")
            if follow:
                follow = re.sub(r"^[a-z]+://", "", follow.strip().lower()).split("/")[0]
                if follow and follow not in {server.lower(), IANA_WHOIS}:
                    second = ctx.http.tcp_query(follow, domain)
                    if second:
                        raw_parts.append(f"; {follow}\n{second}")
                        merge_record(record, parse_whois_raw(second))
                        record.sources.append(f"whois:{follow}")
    record.raw = "\n\n".join(raw_parts).strip()
    if not record.sources and registry_answered and not server:
        record.unavailable_reason = "no_whois_server"
    if record.sources:
        record.privacy = detect_privacy(record)
    else:
        record.privacy = {"enabled": None, "indicators": [], "visible_emails": [], "note": "No registration data available"}
    return record


def registration_state(ctx: ScanContext, domain: str) -> Optional[bool]:
    cache = ctx.recall("whois_dns.registration_cache")
    if cache is None:
        cache = {}
        ctx.share("whois_dns.registration_cache", cache)
    if domain in cache:
        return cache[domain]
    state: Optional[bool] = None
    response = ctx.http.get(RDAP_DOMAIN.format(domain=urllib.parse.quote(domain)), headers={"Accept": "application/rdap+json, application/json"}, max_body=65536)
    if response.status == 404:
        state = False
    elif response.status == 200:
        state = True
    if state is None:
        signals = load_signature("dns", "privacy_hints.json")["unregistered_signals"]
        iana = ctx.http.tcp_query(IANA_WHOIS, domain)
        server = first(*whois_field(iana, ["whois", "refer"])) if iana else None
        if server:
            raw = ctx.http.tcp_query(server, domain).lower()
            if raw:
                state = not any(signal in raw for signal in signals)
    cache[domain] = state
    return state


class WhoisCheck(Check):
    module = MODULE
    name = "whois"
    description = "WHOIS and RDAP registration data with expiry, lock and privacy analysis"
    passive = True
    domain_only = True

    def run(self) -> dict[str, Any]:
        domain = self.ctx.target.registered_domain
        forced = self.option("server")
        record = lookup_domain(self.ctx, domain, forced)
        if not record.sources:
            if record.unavailable_reason:
                tld = domain.rsplit(".", 1)[-1].lower()
                self.add(
                    "WHOIS-UNAVAILABLE",
                    f"WHOIS data is not available for .{tld} domains",
                    "info",
                    f"The .{tld} registry does not publish a WHOIS or RDAP service that can be queried automatically.",
                    {"domain": domain, "tld": tld, "reason": record.unavailable_reason, "lookup_url": record.lookup_url},
                    confidence="high",
                )
            else:
                self.fail(f"no WHOIS or RDAP data retrieved for {domain}")
        record.days_until_expiry = days_until(record.expires)
        self.ctx.share("whois_dns.whois", record.to_dict(include_raw=False))
        self._analyze(domain, record)
        data = record.to_dict()
        data["domain"] = domain
        return data

    def _analyze(self, domain: str, record: WhoisRecord) -> None:
        warning_days = int(self.option("expiry_warning_days", 30))
        new_days = int(self.option("new_domain_days", 30))
        left = record.days_until_expiry
        if left is not None:
            if left < 0:
                self.add("WHOIS-EXPIRED", "Domain registration has expired", "critical", f"Expiry date {record.expires} is in the past.", {"expires": record.expires, "days": left})
            elif left <= 7:
                self.add("WHOIS-EXPIRY-IMMINENT", "Domain expires within 7 days", "high", f"{left} days remaining.", {"expires": record.expires, "days": left})
            elif left <= warning_days:
                self.add("WHOIS-EXPIRY-SOON", f"Domain expires within {warning_days} days", "medium", f"{left} days remaining.", {"expires": record.expires, "days": left})
        age = days_since(record.created)
        if age is not None and 0 <= age <= new_days:
            self.add("WHOIS-NEW-DOMAIN", "Recently registered domain", "medium", f"Registered {age} days ago.", {"created": record.created, "days": age})
        lowered = [s.lower() for s in record.status]
        risky = [s for s in lowered if any(k in s for k in ("pendingdelete", "redemption", "serverhold", "clienthold"))]
        if risky:
            self.add("WHOIS-STATUS-RISK", "Domain is in a risky registry status", "high", "Hold, redemption or pending delete status can lead to loss or takeover of the domain.", {"status": record.status})
        if record.status and not any("transferprohibited" in s for s in lowered):
            self.add("WHOIS-NO-TRANSFER-LOCK", "No registrar transfer lock", "low", "The domain status does not include a transfer prohibition.", {"status": record.status})
        self._analyze_registrar(domain, record)
        self._analyze_nameserver_sync(domain, record)
        self._analyze_dnssec_state(domain, record)
        self._analyze_term(record, lowered)
        privacy = record.privacy
        if privacy and not privacy.get("enabled") and privacy.get("visible_emails"):
            self.add("WHOIS-CONTACT-EXPOSED", "Registrant contact data is publicly visible", "low", "Contact emails are published without privacy protection.", {"emails": privacy["visible_emails"]})
    def _analyze_registrar(self, domain: str, record: WhoisRecord) -> None:
        if not record.sources:
            return
        policy = load_signature("dns", "registrar_watchlist.json")
        name = (record.registrar or "").strip()
        iana = str(record.registrar_iana_id or "").strip()
        reasons: list[str] = []
        if name and any(re.search(pattern, name, re.I) for pattern in policy["name_patterns"]):
            reasons.append("registrar_name_watchlisted")
        if iana and iana in {str(i) for i in policy["iana_ids"]}:
            reasons.append("registrar_id_watchlisted")
        tld = domain.rsplit(".", 1)[-1]
        if policy["missing_is_untrusted"] and not name and not iana and len(tld) != int(policy["country_code_tld_length"]):
            reasons.append("registrar_missing")
        if reasons:
            self.add(
                "WHOIS-REGISTRAR-UNTRUSTED",
                "Registrar could not be established as trustworthy",
                "low",
                "The registrar is missing, malformed or listed on the configured watchlist, which weakens confidence in the registration data.",
                {"domain": domain, "registrar": name or None, "iana_id": iana or None, "reasons": reasons},
                confidence="medium" if "registrar_missing" in reasons else "high",
            )

    def _analyze_nameserver_sync(self, domain: str, record: WhoisRecord) -> None:
        registry = {n.rstrip(".").lower() for n in record.name_servers if n}
        if not registry or self.ctx.target.is_ip:
            return
        live = {n.rstrip(".").lower() for n in get_basic(self.ctx)["ns"] if n}
        if not live or registry == live:
            return
        self.add(
            "WHOIS-NS-MISMATCH",
            "Registry nameservers differ from live DNS delegation",
            "medium",
            "The nameservers recorded at the registry do not match the NS records served by the zone. This can indicate a delegation change in progress, stale data or an unauthorized modification.",
            {
                "domain": domain,
                "only_in_registry": sorted(registry - live),
                "only_in_dns": sorted(live - registry),
            },
        )

    def _analyze_dnssec_state(self, domain: str, record: WhoisRecord) -> None:
        value = (record.dnssec or "").strip().lower()
        if not value or self.ctx.target.is_ip:
            return
        signed = value in {"signeddelegation", "signed", "yes", "true", "active"} or value.startswith("signed")
        unsigned = value in {"unsigned", "unsigneddelegation", "no", "false", "inactive"}
        if not (signed or unsigned):
            return
        has_ds = self.ctx.dns.resolve(domain, "DS").ok
        if signed and not has_ds:
            self.add(
                "WHOIS-DNSSEC-DS-MISMATCH",
                "Registry reports DNSSEC but no DS record resolves",
                "medium",
                "The registry marks the delegation as signed, yet no DS record is visible in DNS. Validating resolvers may fail to resolve the domain.",
                {"domain": domain, "registry_dnssec": record.dnssec, "ds_present": False},
            )
        elif unsigned and has_ds:
            self.add(
                "WHOIS-DNSSEC-DS-MISMATCH",
                "DS record resolves but registry reports an unsigned delegation",
                "low",
                "A DS record is published while the registry data states the delegation is unsigned, which indicates inconsistent registration data.",
                {"domain": domain, "registry_dnssec": record.dnssec, "ds_present": True},
            )

    def _analyze_term(self, record: WhoisRecord, statuses: list[str]) -> None:
        if any("renewprohibited" in status for status in statuses):
            self.add(
                "WHOIS-RENEW-PROHIBITED",
                "Registry status prohibits renewal",
                "low",
                "A renew prohibition status prevents the domain from being extended and can lead to unexpected expiry.",
                {"status": record.status},
                confidence="high",
            )
        created = parse_datetime(record.created)
        expires = parse_datetime(record.expires)
        years = int(self.option("long_registration_years", 5))
        if created and expires and (expires - created).days >= years * 365:
            self.add(
                "WHOIS-LONG-REGISTRATION",
                f"Registration term of {years} years or more",
                "info",
                "A long registration period reduces the risk of accidental expiry and is a trust signal.",
                {"created": record.created, "expires": record.expires, "years": round((expires - created).days / 365, 1)},
            )
