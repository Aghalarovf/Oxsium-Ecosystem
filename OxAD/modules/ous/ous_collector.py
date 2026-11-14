from __future__ import annotations

import logging
import re

from core.models import ADOU
from core.session import Session
from modules.base import BaseModule, ModuleResult
from utils.adutils import entry_guid, ldap_generalized_time_to_iso, normalize_value, safe_int

logger = logging.getLogger(__name__)

_OU_ATTRS = [
    "distinguishedName",
    "name",
    "objectGUID",
    "gPLink",
    "gPOptions",
    "description",
    "managedBy",
    "isCriticalSystemObject",
    "whenCreated",
    "whenChanged",
]

_GPLINK_SEGMENT_RE = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.IGNORECASE)
_GPO_GUID_RE = re.compile(r"cn=(\{[0-9a-f\-]{36}\})", re.IGNORECASE)

_GPLINK_DISABLED = 0x1
_GPLINK_ENFORCED = 0x2
_GPOPTIONS_BLOCK_INHERITANCE = 0x1


def _parse_gplink(raw: str) -> list[dict]:
    if not raw:
        return []

    segments = _GPLINK_SEGMENT_RE.findall(raw)
    total = len(segments)
    links: list[dict] = []

    for index, (gpo_dn, option) in enumerate(segments):
        gpo_dn = gpo_dn.strip()
        opt = safe_int(option)
        guid_match = _GPO_GUID_RE.search(gpo_dn)
        links.append(
            {
                "gpo_dn": gpo_dn,
                "gpo_guid": guid_match.group(1).upper() if guid_match else None,
                "order": total - index,
                "link_enabled": not (opt & _GPLINK_DISABLED),
                "enforced": bool(opt & _GPLINK_ENFORCED),
            }
        )

    return links


def _parent_dn(dn: str) -> str:
    escaped = False
    for index, char in enumerate(dn):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ",":
            return dn[index + 1:]
    return ""


def _fetch_children(ldap, ou_dn: str) -> list[str]:
    try:
        entries = ldap.search(ou_dn, "(objectClass=*)", ["distinguishedName"], scope="LEVEL")
    except Exception as exc:
        logger.warning("child enumeration failed for %s: %s", ou_dn, exc)
        return []

    return [str(entry["distinguishedName"].value) for entry in entries]


class OusModule(BaseModule):
    name = "ous"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(objectClass=organizationalUnit)", _OU_ATTRS)
        except Exception as exc:
            logger.warning("ous collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        ous: list[ADOU] = []
        child_ous_by_parent: dict[str, list[str]] = {}

        for entry in entries:
            gplink_raw = str(normalize_value(entry["gPLink"].value) or "")
            gpoptions = safe_int(normalize_value(entry["gPOptions"].value))
            dn = str(entry["distinguishedName"].value)

            child_ous_by_parent.setdefault(_parent_dn(dn).lower(), []).append(dn)

            ous.append(
                ADOU(
                    dn=dn,
                    name=str(normalize_value(entry["name"].value)),
                    object_guid=entry_guid(entry),
                    gplink=_parse_gplink(gplink_raw),
                    blocks_inheritance=bool(gpoptions & _GPOPTIONS_BLOCK_INHERITANCE),
                    children=_fetch_children(ldap, dn),
                    description=normalize_value(entry["description"].value),
                    managed_by=normalize_value(entry["managedBy"].value),
                    is_critical_system_object=bool(normalize_value(entry["isCriticalSystemObject"].value)),
                    when_created=ldap_generalized_time_to_iso(normalize_value(entry["whenCreated"].value)),
                    when_changed=ldap_generalized_time_to_iso(normalize_value(entry["whenChanged"].value)),
                )
            )

        for ou in ous:
            ou.child_ous = child_ous_by_parent.get(ou.dn.lower(), [])

        result = {"success": True, "count": len(ous), "error": None, "meta": {}}
        return ModuleResult(ous, result)