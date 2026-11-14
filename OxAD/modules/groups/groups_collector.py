from __future__ import annotations

import logging

from ldap3 import BASE
from ldap3.utils.conv import escape_filter_chars

from core.models import ADGroup
from core.session import Session
from modules.base import BaseModule, ModuleResult
from utils.adutils import (
    ldap_generalized_time_to_iso,
    normalize_value,
    normalize_values,
    safe_int,
)
from utils.sid_utils import rid_from_sid, sid_bytes_to_str

logger = logging.getLogger(__name__)

_GROUP_ATTRS = [
    "distinguishedName",
    "name",
    "sAMAccountName",
    "objectSid",
    "member",
    "memberOf",
    "description",
    "groupType",
    "adminCount",
    "isCriticalSystemObject",
    "managedBy",
    "whenCreated",
    "whenChanged",
    "info",
    "primaryGroupToken",
]
_MEMBER_ATTRS = ["distinguishedName", "name", "sAMAccountName", "objectSid", "objectClass"]
_MEMBER_RANGE_STEP = 1500

_SD_FLAGS_DACL = 0x04          # request only the DACL part of nTSecurityDescriptor
_SE_DACL_PROTECTED = 0x1000    # DACL inheritance disabled (set on AdminSDHolder-protected objects)

# Domain-relative RIDs / built-in RIDs of well-known privileged groups.
_PRIVILEGED_RIDS = {
    512,  # Domain Admins
    518,  # Schema Admins
    519,  # Enterprise Admins
    526,  # Key Admins
    527,  # Enterprise Key Admins
    544,  # Administrators
    548,  # Account Operators
    549,  # Server Operators
    550,  # Print Operators
    551,  # Backup Operators
}

# Default primary groups of (nearly) every user / computer. Enumerating their
# primaryGroupID members would return every account in the domain, so they are skipped.
_SKIP_PRIMARY_MEMBER_RIDS = {513, 515}


def _fetch_ranged_members(conn, group_dn: str) -> list[str]:
    members: list[str] = []
    low = 0

    while True:
        attr_name = f"member;range={low}-*"
        conn.search(search_base=group_dn, search_filter="(objectClass=*)", search_scope=BASE, attributes=[attr_name])
        if not conn.entries:
            break

        entry = conn.entries[0]
        returned_attr = next((attr for attr in entry.entry_attributes if attr.startswith("member")), None)
        if not returned_attr:
            break

        values = [str(value) for value in entry[returned_attr].values]
        members.extend(values)

        if returned_attr.endswith("-*") or ";range=" not in returned_attr:
            break

        high = int(returned_attr.rsplit("-", 1)[-1])
        low = high + 1

    return members


def _member_dn(entry) -> str:
    return str(entry["distinguishedName"].value or "")


def _member_record(entry) -> dict:
    dn = _member_dn(entry)
    raw_sid = entry["objectSid"].raw_values
    sid = sid_bytes_to_str(raw_sid[0]) if raw_sid else None
    object_classes = {str(value).lower() for value in entry["objectClass"].values}
    is_group = "group" in object_classes
    is_computer = "computer" in object_classes
    is_user = "user" in object_classes and not is_computer  # computer objects also carry objectClass "user"
    return {
        "name": str(normalize_value(entry["name"].value) or normalize_value(entry["sAMAccountName"].value) or ""),
        "sid": sid,
        "dn": dn,
        "is_user": is_user,
        "is_computer": is_computer,
        "is_group": is_group,
    }


def _resolve_members(ldap, base_dn, member_dns: set[str]) -> dict[str, dict]:
    if not member_dns:
        return {}

    clauses = [
        f"(distinguishedName={escape_filter_chars(dn)})"
        for dn in sorted(member_dns)
    ]
    resolved: dict[str, dict] = {}
    for offset in range(0, len(clauses), 100):
        member_filter = "(|" + "".join(clauses[offset:offset + 100]) + ")"
        try:
            for entry in ldap.search(base_dn, member_filter, _MEMBER_ATTRS):
                record = _member_record(entry)
                if record["dn"]:
                    resolved[record["dn"].lower()] = record
        except Exception as exc:
            logger.warning("group member resolution failed for batch %d: %s", offset // 100 + 1, exc)
    return resolved


def _fetch_acl_protected(ldap, base_dn) -> dict[str, bool]:
    """Map lower-cased group DN -> True when the DACL has inheritance disabled."""
    from ldap3.protocol.microsoft import security_descriptor_control

    result: dict[str, bool] = {}
    try:
        entries = ldap.search(
            base_dn,
            "(objectCategory=group)",
            ["distinguishedName", "nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=_SD_FLAGS_DACL),
        )
    except Exception as exc:
        logger.warning("group ACL protection lookup failed: %s", exc)
        return result

    for entry in entries:
        dn = str(entry["distinguishedName"].value or "").lower()
        raw = entry["nTSecurityDescriptor"].raw_values
        if not dn or not raw or len(raw[0]) < 4:
            continue
        control = int.from_bytes(raw[0][2:4], "little")
        result[dn] = bool(control & _SE_DACL_PROTECTED)
    return result


def _fetch_primary_group_members(ldap, base_dn, rid: int) -> list[str]:
    try:
        entries = ldap.search(base_dn, f"(primaryGroupID={int(rid)})", ["distinguishedName"])
    except Exception as exc:
        logger.warning("primary group member lookup failed for RID %s: %s", rid, exc)
        return []
    return [str(e["distinguishedName"].value) for e in entries if e["distinguishedName"].value]


class GroupsModule(BaseModule):
    name = "groups"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(objectCategory=group)", _GROUP_ATTRS)
        except Exception as exc:
            logger.warning("groups collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        groups: list[ADGroup] = []
        member_dns: set[str] = set()
        acl_protected = _fetch_acl_protected(ldap, session.base_dn)

        for entry in entries:
            sid_raw = entry["objectSid"].raw_values
            sid = sid_bytes_to_str(sid_raw[0]) if sid_raw else None
            group_dn = str(entry["distinguishedName"].value)

            members = list(normalize_values(entry["member"].value))
            if members and len(members) % _MEMBER_RANGE_STEP == 0:
                try:
                    members = _fetch_ranged_members(ldap.conn, group_dn)
                except Exception as exc:
                    logger.warning("ranged member retrieval failed for %s: %s", group_dn, exc)

            member_dns.update(str(member_dn) for member_dn in members if member_dn)

            group_type = safe_int(normalize_value(entry["groupType"].value))
            admin_count = safe_int(normalize_value(entry["adminCount"].value))
            rid = rid_from_sid(sid) if sid else None

            # Members whose *primary group* is this group are not listed in "member".
            if sid and sid.startswith("S-1-5-21-") and rid is not None and rid not in _SKIP_PRIMARY_MEMBER_RIDS:
                known = {str(m).lower() for m in members}
                for primary_dn in _fetch_primary_group_members(ldap, session.base_dn, rid):
                    if primary_dn.lower() not in known:
                        members.append(primary_dn)
                        known.add(primary_dn.lower())
                        member_dns.add(primary_dn)

            groups.append(
                ADGroup(
                    dn=group_dn,
                    name=str(normalize_value(entry["name"].value)),
                    sid=sid,
                    members=[{"dn": str(member_dn)} for member_dn in members if member_dn],
                    member_of=normalize_values(entry["memberOf"].value),
                    description=normalize_value(entry["description"].value),
                    sam_account_name=normalize_value(entry["sAMAccountName"].value),
                    group_type=group_type,
                    security_enabled=group_type < 0,
                    admin_count=admin_count,
                    is_critical_system_object=bool(normalize_value(entry["isCriticalSystemObject"].value)),
                    managed_by=normalize_value(entry["managedBy"].value),
                    when_created=ldap_generalized_time_to_iso(normalize_value(entry["whenCreated"].value)),
                    when_changed=ldap_generalized_time_to_iso(normalize_value(entry["whenChanged"].value)),
                    info=normalize_value(entry["info"].value),
                    rid=rid,
                    primary_group_token=safe_int(normalize_value(entry["primaryGroupToken"].value), default=None),
                    isaclprotected=acl_protected.get(group_dn.lower(), False),
                    is_privileged=admin_count > 0 or rid in _PRIVILEGED_RIDS,
                    is_protected=admin_count > 0,
                )
            )

        resolved_members = _resolve_members(ldap, session.base_dn, member_dns)
        for group in groups:
            group.members = [
                resolved_members.get(member["dn"].lower(), member)
                for member in group.members
            ]

        result = {"success": True, "count": len(groups), "error": None, "meta": {}}
        return ModuleResult(groups, result)