from __future__ import annotations

import logging

from core.models import ADComputer
from core.session import Session
from modules.base import BaseModule, ModuleResult
from utils.adutils import (
    ldap_generalized_time_to_iso,
    ldap_timestamp_to_iso,
    normalize_value,
    normalize_values,
    parse_rbcd_sd,
    resolve_sids_to_names,
    safe_int,
)
from utils.constants import UAC_FLAGS
from utils.dns_utils import enumerate_ips
from utils.sid_utils import sid_bytes_to_str

logger = logging.getLogger(__name__)

_COMPUTER_ATTRS = [
    "distinguishedName",
    "name",
    "sAMAccountName",
    "objectSid",
    "operatingSystem",
    "operatingSystemVersion",
    "dNSHostName",
    "userAccountControl",
    "servicePrincipalName",
    "lastLogonTimestamp",
    "pwdLastSet",
    "description",
    "primaryGroupID",
    "isCriticalSystemObject",
    "msDS-SupportedEncryptionTypes",
    "whenCreated",
    "whenChanged",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
]


def _domain_from_base_dn(base_dn: str | None) -> str:
    parts = [
        part.split("=", 1)[1].strip()
        for part in (base_dn or "").split(",")
        if part.strip().upper().startswith("DC=") and "=" in part
    ]
    return ".".join(parts)


def _lookup_name(computer: ADComputer, domain: str) -> str:
    if computer.dns_hostname:
        return str(computer.dns_hostname)
    host = computer.sam_account_name.rstrip("$") or computer.name
    return f"{host}.{domain}" if domain else host


def _enumerate_ip_addresses(session: Session, computers: list[ADComputer]) -> dict:
    domain = _domain_from_base_dn(session.base_dn)
    hosts = {computer.dn: _lookup_name(computer, domain) for computer in computers}
    resolved = enumerate_ips(hosts, session.target)
    found = 0
    for computer in computers:
        ipv4, ipv6 = resolved.get(computer.dn, ([], []))
        computer.ipv4_addresses = ipv4
        computer.ipv6_addresses = ipv6
        if ipv4 or ipv6:
            found += 1
    logger.info("ip enumeration resolved %d of %d computers", found, len(computers))
    return {
        "enabled": True,
        "dns_server": session.target,
        "computers": len(computers),
        "resolved": found,
        "unresolved": len(computers) - found,
    }


class ComputersModule(BaseModule):
    name = "computers"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(objectCategory=computer)", _COMPUTER_ATTRS)
        except Exception as exc:
            logger.warning("computers collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        # Pass 1: pull every entry's plain attributes plus its parsed RBCD
        # descriptor, and collect every trustee SID seen across all
        # computers so they can be resolved to names in one extra search.
        staged: list[dict] = []
        all_rbcd_sid_bytes: list[bytes] = []

        for entry in entries:
            sid_raw = entry["objectSid"].raw_values
            sid = sid_bytes_to_str(sid_raw[0]) if sid_raw else None
            uac = safe_int(normalize_value(entry["userAccountControl"].value))
            rbcd_raw = entry["msDS-AllowedToActOnBehalfOfOtherIdentity"].raw_values
            rbcd = parse_rbcd_sd(rbcd_raw[0] if rbcd_raw else None)
            all_rbcd_sid_bytes.extend(rbcd["principal_sid_bytes"])

            staged.append(
                {
                    "dn": str(entry["distinguishedName"].value),
                    "name": str(normalize_value(entry["name"].value)),
                    "sam_account_name": str(normalize_value(entry["sAMAccountName"].value)),
                    "sid": sid,
                    "operating_system": normalize_value(entry["operatingSystem"].value),
                    "dns_hostname": normalize_value(entry["dNSHostName"].value),
                    "enabled": not bool(uac & UAC_FLAGS["ACCOUNTDISABLE"]),
                    "trusted_for_delegation": bool(uac & UAC_FLAGS["TRUSTED_FOR_DELEGATION"]),
                    "spns": normalize_values(entry["servicePrincipalName"].value),
                    "uac": uac,
                    "operating_system_version": normalize_value(entry["operatingSystemVersion"].value),
                    "last_logon": ldap_timestamp_to_iso(normalize_value(entry["lastLogonTimestamp"].value)),
                    "pwd_last_set": ldap_timestamp_to_iso(normalize_value(entry["pwdLastSet"].value)),
                    "description": normalize_value(entry["description"].value),
                    "primary_group_id": safe_int(normalize_value(entry["primaryGroupID"].value)),
                    "is_critical_system_object": bool(normalize_value(entry["isCriticalSystemObject"].value)),
                    "supported_encryption_types": safe_int(
                        normalize_value(entry["msDS-SupportedEncryptionTypes"].value)
                    ),
                    "when_created": ldap_generalized_time_to_iso(normalize_value(entry["whenCreated"].value)),
                    "when_changed": ldap_generalized_time_to_iso(normalize_value(entry["whenChanged"].value)),
                    "allowed_to_delegate_to": normalize_values(entry["msDS-AllowedToDelegateTo"].value),
                    "rbcd": rbcd,
                }
            )

        sid_name_map = resolve_sids_to_names(ldap, session.base_dn, all_rbcd_sid_bytes)

        # Pass 2: build the final records, resolving each RBCD trustee SID
        # to a name via the batch lookup above (falling back to the raw SID
        # string for foreign/deleted principals that didn't resolve).
        computers: list[ADComputer] = []
        for row in staged:
            rbcd = row.pop("rbcd")
            computers.append(
                ADComputer(
                    **row,
                    rbcd_configured=rbcd["enabled"],
                    rbcd_enabled=rbcd["enabled"],
                    rbcd_sddl=rbcd["sddl"],
                    rbcd_principals=rbcd["principal_sids"],
                    rbcd_principal_names=[
                        sid_name_map.get(s, s) for s in rbcd["principal_sids"]
                    ],
                )
            )

        meta: dict = {}
        if session.enumerate_ip:
            meta["ip_enumeration"] = _enumerate_ip_addresses(session, computers)

        result = {"success": True, "count": len(computers), "error": None, "meta": meta}
        return ModuleResult(computers, result)