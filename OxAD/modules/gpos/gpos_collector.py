from __future__ import annotations

import logging
import re

from ldap3.utils.conv import escape_filter_chars

from core.models import ADGPO
from core.session import Session
from modules.base import BaseModule, ModuleResult
from utils.adutils import ldap_generalized_time_to_iso, normalize_value, normalize_values, safe_int

logger = logging.getLogger(__name__)

_GPO_ATTRS = [
    "distinguishedName",
    "displayName",
    "cn",
    "gPCFileSysPath",
    "flags",
    "versionNumber",
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "gPCWQLFilter",
    "isCriticalSystemObject",
    "whenCreated",
    "whenChanged",
]

# A gPLink value is a run of "[LDAP://<container-or-GPO DN>;<option>]"
# segments, one per GPO linked to that container, e.g.
#   [LDAP://cn={GUID},cn=policies,cn=system,DC=...;2][LDAP://...;0]
# <option> is a 2-bit mask, NOT the GPO's own "flags" attribute:
#   0 = link enabled,  not enforced      2 = link enabled,  enforced
#   1 = link disabled, not enforced      3 = link disabled, enforced
_GPLINK_SEGMENT_RE = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.IGNORECASE)

# GPO-level "flags" (distinct from the per-link gPLink option above): a
# 2-bit mask on the GPO object itself saying which half of the policy is
# turned off, independent of where/how it's linked.
_GPFLAGS_USER_DISABLED = 0x1
_GPFLAGS_COMPUTER_DISABLED = 0x2


def _find_linked_containers(ldap, base_dn: str, gpo_dn: str) -> list[dict]:
    """Find every container that links this GPO and, for each one, the
    REAL per-link Link Enabled / Enforced state - parsed from that
    container's own gPLink suffix, not from the GPO's "flags" attribute
    (which encodes something unrelated: see _GPFLAGS_* above).
    """
    try:
        entries = ldap.search(
            base_dn,
            f"(gPLink=*{escape_filter_chars(gpo_dn)}*)",
            ["distinguishedName", "gPLink"],
        )
    except Exception as exc:
        logger.warning("linked container lookup failed for %s: %s", gpo_dn, exc)
        return []

    gpo_dn_lower = gpo_dn.strip().lower()
    links: list[dict] = []
    for entry in entries:
        container_dn = str(entry["distinguishedName"].value)
        for raw_link in normalize_values(entry["gPLink"].value):
            for seg_dn, option in _GPLINK_SEGMENT_RE.findall(str(raw_link)):
                if seg_dn.strip().lower() != gpo_dn_lower:
                    continue
                opt = safe_int(option)
                links.append(
                    {
                        "dn": container_dn,
                        "link_enabled": opt in (0, 2),
                        "enforced": opt in (2, 3),
                    }
                )

    return links


class GposModule(BaseModule):
    name = "gpos"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(objectClass=groupPolicyContainer)", _GPO_ATTRS)
        except Exception as exc:
            logger.warning("gpos collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        gpos: list[ADGPO] = []

        for entry in entries:
            flags = safe_int(normalize_value(entry["flags"].value))
            dn = str(entry["distinguishedName"].value)
            user_disabled = bool(flags & _GPFLAGS_USER_DISABLED)
            computer_disabled = bool(flags & _GPFLAGS_COMPUTER_DISABLED)
            links = _find_linked_containers(ldap, session.base_dn, dn)

            gpos.append(
                ADGPO(
                    dn=dn,
                    name=str(normalize_value(entry["displayName"].value)),
                    guid=str(normalize_value(entry["cn"].value)),
                    file_system_path=normalize_value(entry["gPCFileSysPath"].value),
                    linked_ous=links,
                    enabled=not (user_disabled and computer_disabled),
                    user_settings_disabled=user_disabled,
                    computer_settings_disabled=computer_disabled,
                    enforced=any(link["enforced"] for link in links),
                    is_critical_system_object=bool(normalize_value(entry["isCriticalSystemObject"].value)),
                    version_number=safe_int(normalize_value(entry["versionNumber"].value)),
                    machine_extension_names=normalize_value(entry["gPCMachineExtensionNames"].value),
                    user_extension_names=normalize_value(entry["gPCUserExtensionNames"].value),
                    wmi_filter=normalize_value(entry["gPCWQLFilter"].value),
                    when_created=ldap_generalized_time_to_iso(normalize_value(entry["whenCreated"].value)),
                    when_changed=ldap_generalized_time_to_iso(normalize_value(entry["whenChanged"].value)),
                )
            )

        result = {"success": True, "count": len(gpos), "error": None, "meta": {}}
        return ModuleResult(gpos, result)