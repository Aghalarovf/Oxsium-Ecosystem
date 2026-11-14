from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

AUTH_EKU = "1.3.6.1.5.5.7.3.2"
PKINIT_CLIENT_AUTH_EKU = "1.3.6.1.5.2.3.4"
SMARTCARD_LOGON_EKU = "1.3.6.1.4.1.311.20.2.2"
ANY_PURPOSE = "2.5.29.37.0"
AUTH_EKUS = {AUTH_EKU, PKINIT_CLIENT_AUTH_EKU, SMARTCARD_LOGON_EKU, ANY_PURPOSE}
REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
WRITE_RIGHTS = {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner", "WriteProperty"}
ENROLL_RIGHTS = {"Certificate-Enrollment", "Certificate-AutoEnrollment", "All-Extended-Rights", "GenericAll"}
ACE_ALLOW_TYPES = {0, 5}
ACE_DENY_TYPES = {1, 6}
ADMIN_SIDS = {"S-1-5-18", "S-1-5-32-544"}
ADMIN_SUFFIXES = ("-512", "-516", "-519")


def values(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def integer(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return default


def oids(template: dict) -> set[str]:
    raw = template.get("raw", {})
    return {str(value) for key in ("pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy") for value in values(raw.get(key))}


def _ace_kind(ace: dict) -> str | None:
    raw = ace.get("ace_type_raw")
    if raw is not None:
        raw = integer(raw, -1)
        if raw in ACE_ALLOW_TYPES:
            return "allow"
        if raw in ACE_DENY_TYPES:
            return "deny"
    label = str(ace.get("ace_type") or ace.get("type") or "").lower()
    if label == "allow":
        return "allow"
    if label == "deny":
        return "deny"
    return None


def _ace_sid(ace: dict) -> str:
    return str(ace.get("principal_sid") or ace.get("sid") or "")


def enrolled(template: dict) -> tuple[bool, str | None, list[str]]:
    denied: set[str] = set()
    allowed: list[tuple[str, list[str]]] = []
    for ace in template.get("acl", []):
        sid = _ace_sid(ace)
        rights = set(values(ace.get("rights") or ace.get("right")))
        kind = _ace_kind(ace)
        if kind == "deny":
            if rights & ENROLL_RIGHTS or integer(ace.get("mask")) & 0x100:
                denied.add(sid)
        elif kind == "allow":
            allowed.append((sid, sorted(rights)))
    for sid, rights in allowed:
        if sid not in denied and not is_admin(sid) and ENROLL_RIGHTS.intersection(rights):
            return True, sid, rights
    return False, None, []


def writable(template: dict) -> tuple[bool, str | None, list[str]]:
    for ace in template.get("acl", []):
        sid = _ace_sid(ace)
        rights = set(values(ace.get("rights") or ace.get("right")))
        if _ace_kind(ace) == "allow" and not is_admin(sid):
            matched = sorted(WRITE_RIGHTS.intersection(rights))
            if matched:
                return True, sid, matched
    return False, None, []


def is_admin(sid: str) -> bool:
    return sid in ADMIN_SIDS or sid.endswith(ADMIN_SUFFIXES)


def subject_supplied(template: dict) -> bool:
    raw = template.get("raw", {})
    return bool(integer(raw.get("msPKI-Certificate-Name-Flag")) & 1)


def manager_approval(template: dict) -> bool:
    return bool(integer(template.get("raw", {}).get("msPKI-Enrollment-Flag")) & 2)


def published(template: dict, services: list[dict]) -> bool:
    name = str(template.get("name") or template.get("raw", {}).get("cn") or "").lower()
    for service in services:
        for item in values(service.get("raw", {}).get("certificateTemplates")):
            if str(item).lower() in {name, f"cn={name}"}:
                return True
    return False


def finding(rule: str, target: dict, detail: dict, confidence: str = "confirmed") -> dict:
    return {
        "rule": rule,
        "severity": "high" if rule.startswith("ESC") else "medium",
        "status": confidence,
        "target": target.get("dn") or target.get("name"),
        "detail": detail,
    }


def parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def expiry_findings(record: dict) -> list[dict]:
    raw = record.get("raw", {})
    result = []
    for key in ("notAfter", "expiration", "valid_to"):
        parsed = parse_iso(raw.get(key))
        if parsed:
            now = datetime.now(timezone.utc)
            if parsed <= now:
                result.append(f"Certificate expired: {key}")
            elif (parsed - now).days <= 30:
                result.append(f"Certificate expires within 30 days: {key}")
    return result