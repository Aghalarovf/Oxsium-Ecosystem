from __future__ import annotations

import logging

from core.models import ADUser
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
from utils.sid_utils import sid_bytes_to_str

logger = logging.getLogger(__name__)

_USER_ATTRS = [
    "distinguishedName",
    "sAMAccountName",
    "objectSid",
    "displayName",
    "userAccountControl",
    "adminCount",
    "servicePrincipalName",
    "memberOf",
    "pwdLastSet",
    "lastLogonTimestamp",
    "description",
    "mail",
    "sIDHistory",
    "accountExpires",
    "lockoutTime",
    "badPwdCount",
    "whenCreated",
    "whenChanged",
    "primaryGroupID",
    "msDS-SupportedEncryptionTypes",
    "homeDirectory",
    "scriptPath",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "badPasswordTime",
    "logonCount",
    "msDS-User-Account-Control-Computed",
]

_UF_LOCKOUT = 0x0010  # UF_LOCKOUT in msDS-User-Account-Control-Computed


class UsersModule(BaseModule):
    name = "users"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(&(objectCategory=person)(objectClass=user))", _USER_ATTRS)
        except Exception as exc:
            logger.warning("users collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        # Pass 1: plain attributes plus each user's parsed RBCD descriptor,
        # collecting every trustee SID across all users for one batch
        # resolve (see computers_collector.py for the same pattern).
        staged: list[dict] = []
        all_rbcd_sid_bytes: list[bytes] = []

        for entry in entries:
            sid_raw = entry["objectSid"].raw_values
            sid = sid_bytes_to_str(sid_raw[0]) if sid_raw else None
            uac = safe_int(normalize_value(entry["userAccountControl"].value))
            sid_history_raw = entry["sIDHistory"].raw_values
            rbcd_raw = entry["msDS-AllowedToActOnBehalfOfOtherIdentity"].raw_values
            rbcd = parse_rbcd_sd(rbcd_raw[0] if rbcd_raw else None)
            all_rbcd_sid_bytes.extend(rbcd["principal_sid_bytes"])
            uac_computed = safe_int(normalize_value(entry["msDS-User-Account-Control-Computed"].value))

            staged.append(
                {
                    "dn": str(entry["distinguishedName"].value),
                    "sam_account_name": str(normalize_value(entry["sAMAccountName"].value)),
                    "sid": sid,
                    "display_name": normalize_value(entry["displayName"].value),
                    "enabled": not bool(uac & UAC_FLAGS["ACCOUNTDISABLE"]),
                    "admin_count": safe_int(normalize_value(entry["adminCount"].value)),
                    "spns": normalize_values(entry["servicePrincipalName"].value),
                    "uac": uac,
                    "member_of": normalize_values(entry["memberOf"].value),
                    "pwd_last_set": ldap_timestamp_to_iso(normalize_value(entry["pwdLastSet"].value)),
                    "last_logon": ldap_timestamp_to_iso(normalize_value(entry["lastLogonTimestamp"].value)),
                    "description": normalize_value(entry["description"].value),
                    "mail": normalize_value(entry["mail"].value),
                    "sid_history": [sid_bytes_to_str(raw) for raw in sid_history_raw],
                    "account_expires": ldap_timestamp_to_iso(normalize_value(entry["accountExpires"].value)),
                    "lockout_time": ldap_timestamp_to_iso(normalize_value(entry["lockoutTime"].value)),
                    "bad_pwd_count": safe_int(normalize_value(entry["badPwdCount"].value)),
                    "when_created": ldap_generalized_time_to_iso(normalize_value(entry["whenCreated"].value)),
                    "when_changed": ldap_generalized_time_to_iso(normalize_value(entry["whenChanged"].value)),
                    "primary_group_id": safe_int(normalize_value(entry["primaryGroupID"].value), default=None),
                    "supported_encryption_types": safe_int(
                        normalize_value(entry["msDS-SupportedEncryptionTypes"].value), default=None
                    ),
                    "home_directory": normalize_value(entry["homeDirectory"].value),
                    "script_path": normalize_value(entry["scriptPath"].value),
                    "allowed_to_delegate_to": normalize_values(entry["msDS-AllowedToDelegateTo"].value),
                    "rbcd": rbcd,
                    "bad_pwd_time": ldap_timestamp_to_iso(normalize_value(entry["badPasswordTime"].value)),
                    "logon_count": safe_int(normalize_value(entry["logonCount"].value), default=None),
                    "locked_out": bool(uac_computed & _UF_LOCKOUT),
                }
            )

        sid_name_map = resolve_sids_to_names(ldap, session.base_dn, all_rbcd_sid_bytes)

        users: list[ADUser] = []
        for row in staged:
            rbcd = row.pop("rbcd")
            users.append(
                ADUser(
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

        result = {"success": True, "count": len(users), "error": None, "meta": {}}
        return ModuleResult(users, result)