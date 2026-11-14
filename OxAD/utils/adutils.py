from __future__ import annotations

import uuid
from datetime import datetime, timezone

_FILETIME_EPOCH_DELTA = 116444736000000000
_FILETIME_NEVER = 9223372036854775807


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def get_bind_user(username: str, domain: str) -> str:
    return f"{domain}\\{username}"


def normalize_value(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def entry_guid(entry) -> str | None:
    raw_values = entry["objectGUID"].raw_values
    if not raw_values:
        return None
    try:
        return str(uuid.UUID(bytes_le=bytes(raw_values[0]))).upper()
    except (ValueError, TypeError):
        return None


def normalize_values(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def ldap_timestamp_to_iso(value) -> str | None:
    """Convert an LDAP FILETIME value (pwdLastSet, lastLogonTimestamp,
    accountExpires, lockoutTime, ...) to an ISO-8601 string.

    ldap3 usually returns these attributes already parsed as ``datetime``
    objects; raw integers (or numeric strings) are handled as well.
    Sentinel values (0 / 1601-01-01 and "never" / 9999-12-31) return None.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if dt.year <= 1601 or dt.year >= 9999:
            return None
        return dt.astimezone(timezone.utc).isoformat()

    raw = safe_int(value, 0)
    if raw in (0, _FILETIME_NEVER):
        return None
    try:
        epoch_seconds = (raw - _FILETIME_EPOCH_DELTA) / 10_000_000
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_rbcd_sd(raw_sd: bytes) -> dict:
    """Parse a msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor
    (the raw bytes from ldap3's ``raw_values``) into its RBCD trustees.

    msDS-AllowedToActOnBehalfOfOtherIdentity is itself a self-relative
    security descriptor whose DACL lists the principals (computers/users)
    allowed to delegate onto the object that carries the attribute - it is
    NOT the object's own nTSecurityDescriptor. Returns
    ``{"enabled": bool, "sddl": str | None, "principal_sids": list[str],
    "principal_sid_bytes": list[bytes]}``. Any failure (impacket missing,
    empty/malformed descriptor) yields the all-empty/False default rather
    than raising, since RBCD is optional on every object.
    """
    result = {"enabled": False, "sddl": None, "principal_sids": [], "principal_sid_bytes": []}
    if not raw_sd:
        return result

    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    except ImportError:
        return result

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=raw_sd)
        dacl = sd["Dacl"]
    except Exception:
        return result
    if dacl is None:
        return result

    sids: list[str] = []
    sid_bytes: list[bytes] = []
    for ace in dacl.aces:
        try:
            ace_sid = ace["Ace"]["Sid"]
            sids.append(ace_sid.formatCanonical())
            sid_bytes.append(ace_sid.getData())
        except Exception:
            continue

    result["principal_sids"] = sids
    result["principal_sid_bytes"] = sid_bytes
    result["enabled"] = bool(sids)
    try:
        result["sddl"] = sd.toSDDL()
    except Exception:
        pass
    return result


def resolve_sids_to_names(ldap, base_dn: str | None, sid_bytes_list) -> dict[str, str]:
    """Batch-resolve raw objectSid bytes (e.g. RBCD trustees) to
    sAMAccountName with a single LDAP search, instead of one round trip per
    principal. Returns ``{sid_string: sam_account_name}``; SIDs that can't
    be resolved (deleted/foreign principals) are simply absent from it, so
    callers should fall back to the SID string.
    """
    from utils.sid_utils import sid_bytes_to_str

    unique = {bytes(b) for b in sid_bytes_list if b}
    if not unique:
        return {}

    try:
        from ldap3.utils.conv import escape_bytes
    except ImportError:
        return {}

    ldap_filter = "(|" + "".join(f"(objectSid={escape_bytes(b)})" for b in unique) + ")"
    try:
        entries = ldap.search(base_dn, ldap_filter, ["sAMAccountName", "objectSid"])
    except Exception:
        return {}

    mapping: dict[str, str] = {}
    for entry in entries:
        sid_raw = entry["objectSid"].raw_values
        if not sid_raw:
            continue
        name = normalize_value(entry["sAMAccountName"].value)
        if name:
            mapping[sid_bytes_to_str(sid_raw[0])] = str(name)
    return mapping


def ldap_generalized_time_to_iso(value) -> str | None:
    """Convert an LDAP Generalized Time value (whenCreated, whenChanged, ...)
    to an ISO-8601 string.

    ldap3 usually hands these back already parsed as ``datetime`` objects,
    but some backends/pools return the raw LDAP string instead
    (e.g. ``20260101120000.0Z`` or ``20260101120000+0400``), so both are
    handled here.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    raw = str(value).strip()
    if not raw:
        return None

    # Strip fractional seconds (".0", ".123") before the timezone marker.
    for marker in ("Z", "+", "-"):
        idx = raw.find(".")
        if idx != -1:
            tz_idx = raw.find(marker, idx)
            if tz_idx != -1:
                raw = raw[:idx] + raw[tz_idx:]
                break
    else:
        if raw.endswith("Z") and "." in raw:
            raw = raw.split(".")[0] + "Z"

    fmts = ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S%z")
    for fmt in fmts:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return None