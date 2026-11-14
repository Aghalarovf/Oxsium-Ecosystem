from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_FUNCTIONAL_LEVELS = {
    "2000": 0,
    "2003 Mixed": 1,
    "2003": 2,
    "2008": 3,
    "2008 R2": 4,
    "2012": 5,
    "2012 R2": 6,
    "2016+": 7,
}

# Modules whose collector output is stored as raw_<name>.jsonl and is turned
# into the final domain_<name>.jsonl by the engine (see engine/pipeline.py).
RAW_MODULES = ("users", "computers", "groups", "ous", "gpos", "cert")

_UAC_ACCOUNTDISABLE = 0x0002
_UAC_DONT_REQUIRE_PREAUTH = 0x400000
_UAC_NOT_DELEGATED = 0x100000
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_DONT_EXPIRE_PASSWORD = 0x10000
_UAC_SMARTCARD_REQUIRED = 0x40000
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


def _record_dict(record: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(record):
        return dataclasses.asdict(record)
    if isinstance(record, dict):
        return dict(record)
    raise TypeError(f"Unsupported JSONL record type: {type(record).__name__}")


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _as_bool(value: Any) -> bool:
    return bool(value)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _name_from_dn(dn: str | None) -> str:
    if not dn:
        return ""
    first = str(dn).split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else first


def _domain_sid_from_sid(sid: str | None) -> str | None:
    if not sid or not str(sid).upper().startswith("S-"):
        return None
    parts = str(sid).split("-")
    return "-".join(parts[:-1]) if len(parts) > 4 else None


def _domain_from_dn(dn: str | None) -> str:
    if not dn:
        return ""
    parts = re.findall(r"DC=([^,]+)", str(dn), flags=re.IGNORECASE)
    return ".".join(parts)


def _split_dn(dn: str | None) -> list[str]:
    if not dn:
        return []
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in str(dn):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _parent_dn_of(dn: str | None) -> str | None:
    parts = _split_dn(dn)
    return ",".join(parts[1:]) if len(parts) > 1 else None


def _ou_depth(dn: str | None) -> int | None:
    parts = _split_dn(dn)
    if not parts:
        return None
    return sum(1 for part in parts if not part.strip().upper().startswith("DC="))


def _user_record(raw: dict[str, Any]) -> dict[str, Any]:
    uac = int(raw.get("uac") or 0)
    sid = raw.get("sid")
    spns = _as_list(raw.get("spns"))
    member_of = _as_list(raw.get("member_of"))
    enabled = _as_bool(raw.get("enabled")) and not (uac & _UAC_ACCOUNTDISABLE)
    return {
        "username": raw.get("sam_account_name") or raw.get("username") or "",
        "dn": raw.get("dn") or "",
        "display_name": raw.get("display_name"),
        "sid": sid,
        "upn": raw.get("upn"),
        "description": raw.get("description"),
        "mail": raw.get("mail"),
        "phone": raw.get("phone"),
        "department": raw.get("department"),
        "title": raw.get("title"),
        "disabled": not enabled,
        "locked_out": _as_bool(raw.get("locked_out")),
        "lockout_time": raw.get("lockout_time"),
        "must_change_pwd": _as_bool(raw.get("must_change_pwd")),
        "smartcard_required": _as_bool(raw.get("smartcard_required")) or bool(uac & _UAC_SMARTCARD_REQUIRED),
        "normal_account": _as_bool(raw.get("normal_account", True)),
        "pwd_never_expires": _as_bool(raw.get("pwd_never_expires")) or bool(uac & _UAC_DONT_EXPIRE_PASSWORD),
        "pwd_not_required": _as_bool(raw.get("pwd_not_required")) or bool(uac & 0x20),
        "pwd_cant_change": _as_bool(raw.get("pwd_cant_change")),
        "preauth_required": not bool(uac & _UAC_DONT_REQUIRE_PREAUTH),
        "admin_count": raw.get("admin_count") or 0,
        "dcsync": _as_bool(raw.get("dcsync")),
        "asrep": _as_bool(raw.get("asrep")) or (enabled and bool(uac & _UAC_DONT_REQUIRE_PREAUTH)),
        "kerberoastable": _as_bool(raw.get("kerberoastable")) or bool(spns and enabled),
        "trusted_for_delegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
        "unconstrained_delegation": bool(uac & _UAC_TRUSTED_FOR_DELEGATION),
        "constrained_delegation": bool(raw.get("constrained_delegation")) or bool(_as_list(raw.get("allowed_to_delegate_to"))),
        "delegation_effective": bool(raw.get("delegation_effective")),
        "delegation_blocked": bool(uac & _UAC_NOT_DELEGATED),
        "trusted_to_auth_for_delegation": bool(raw.get("trusted_to_auth_for_delegation")) or bool(uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
        "protocol_transition_delegation": bool(raw.get("protocol_transition_delegation")) or bool(uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
        "not_delegated": bool(uac & _UAC_NOT_DELEGATED),
        "msds_supportedencryptiontypes": raw.get("supported_encryption_types"),
        "enc_risk_score": raw.get("enc_risk_score"),
        "enc_implicit_rc4": _as_bool(raw.get("enc_implicit_rc4")),
        "when_created": raw.get("when_created"),
        "when_changed": raw.get("when_changed"),
        "last_logon": raw.get("last_logon"),
        "pwd_last_set": raw.get("pwd_last_set"),
        "logon_count": raw.get("logon_count"),
        "domain_sid": raw.get("domain_sid") or _domain_sid_from_sid(sid),
        "primary_group_id": raw.get("primary_group_id"),
        "primary_group_sid": raw.get("primary_group_sid"),
        "bad_pwd_count": raw.get("bad_pwd_count"),
        "bad_pwd_time": raw.get("bad_pwd_time"),
        "account_expires": raw.get("account_expires"),
        "account_never_expires": _as_bool(raw.get("account_never_expires")) or raw.get("account_expires") is None,
        "msds_resultant_pso": raw.get("msds_resultant_pso"),
        "pwd_expiry_time": raw.get("pwd_expiry_time"),
        "has_key_credential_link": _as_bool(raw.get("has_key_credential_link")),
        "script_path": raw.get("script_path"),
        "home_directory": raw.get("home_directory"),
        "home_drive": raw.get("home_drive"),
        "deleted": _as_bool(raw.get("deleted")),
        "deleted_dn": raw.get("deleted_dn"),
        "last_known_parent": raw.get("last_known_parent"),
        "when_deleted": raw.get("when_deleted"),
        "spn": spns,
        "msds_allowedtodelegateto": _as_list(raw.get("allowed_to_delegate_to")),
        "msds_allowedtodelegateto_structurized": _as_list(raw.get("msds_allowedtodelegateto_structurized")),
        "msds_supportedencryptiontypesname": _as_list(raw.get("msds_supportedencryptiontypesname")),
        "msds_supportedencryptiontypes_name": _as_list(raw.get("msds_supportedencryptiontypes_name")),
        "key_credential_link": _as_list(raw.get("key_credential_link")),
        "member_of": member_of,
        "uac": uac,
    }


def _computer_record(raw: dict[str, Any]) -> dict[str, Any]:
    sid = raw.get("sid")
    uac = int(raw.get("uac") or 0)
    name = raw.get("name") or raw.get("computer_name") or ""
    os_name = raw.get("operating_system") or raw.get("os")
    spns = _as_list(raw.get("spns"))
    return {
        "computer_name": name,
        "dns_name": raw.get("dns_hostname") or raw.get("dns_name"),
        "dn": raw.get("dn") or "",
        "display_name": raw.get("display_name") or name,
        "sid": sid,
        "domainsid": raw.get("domainsid") or _domain_sid_from_sid(sid),
        "description": raw.get("description"),
        "location": raw.get("location"),
        "disabled": bool(uac & _UAC_ACCOUNTDISABLE) or not _as_bool(raw.get("enabled", True)),
        "os": os_name,
        "os_version": raw.get("os_version"),
        "os_service_pack": raw.get("os_service_pack"),
        "os_bucket": raw.get("os_bucket"),
        "is_workstation": _as_bool(raw.get("is_workstation")) or (bool(os_name) and "server" not in str(os_name).lower()),
        "is_server": _as_bool(raw.get("is_server")) or (bool(os_name) and "server" in str(os_name).lower()),
        "is_domain_controller": _as_bool(raw.get("is_domain_controller")) or "domain controllers" in str(raw.get("dn", "")).lower(),
        "potential_privileged": _as_bool(raw.get("potential_privileged")),
        "is_stale": _as_bool(raw.get("is_stale")),
        "stale_by_pwd": _as_bool(raw.get("stale_by_pwd")),
        "stale_by_logon": _as_bool(raw.get("stale_by_logon")),
        "has_spn": bool(spns),
        "trusted_for_delegation": _as_bool(raw.get("trusted_for_delegation")),
        "trusted_to_auth_for_delegation": _as_bool(raw.get("trusted_to_auth_for_delegation")),
        "unconstrained_delegation": _as_bool(raw.get("unconstrained_delegation")) or _as_bool(raw.get("trusted_for_delegation")),
        "constrained_delegation": _as_bool(raw.get("constrained_delegation")),
        "protocol_transition_delegation": _as_bool(raw.get("protocol_transition_delegation")),
        "delegation_effective": _as_bool(raw.get("delegation_effective")),
        "rbcd_enabled": _as_bool(raw.get("rbcd_enabled")),
        "rbcd_sddl": raw.get("rbcd_sddl"),
        "has_laps": _as_bool(raw.get("has_laps")),
        "haslaps": _as_bool(raw.get("haslaps")) or _as_bool(raw.get("has_laps")),
        "laps_expiration": raw.get("laps_expiration"),
        "isaclprotected": _as_bool(raw.get("isaclprotected")),
        "primary_group_id": raw.get("primary_group_id"),
        "primary_group_sid": raw.get("primary_group_sid"),
        "kerberoastable": _as_bool(raw.get("kerberoastable")),
        "asrep": _as_bool(raw.get("asrep")),
        "has_shadow_credential": _as_bool(raw.get("has_shadow_credential")),
        "risk_score": raw.get("risk_score"),
        "smb_port_open": _as_bool(raw.get("smb_port_open")),
        "smb_signing_required": raw.get("smb_signing_required"),
        "smb_version": raw.get("smb_version"),
        "is_ip_only": _as_bool(raw.get("is_ip_only")),
        "when_created": raw.get("when_created"),
        "when_changed": raw.get("when_changed"),
        "last_logon": raw.get("last_logon"),
        "pwd_last_set": raw.get("pwd_last_set"),
        "domain_name": raw.get("domain_name") or _domain_from_dn(raw.get("dn")),
        "spn": spns,
        "allowed_to_delegate_to": _as_list(raw.get("allowed_to_delegate_to")),
        "allowed_to_delegate_to_structured": _as_list(raw.get("allowed_to_delegate_to_structured")),
        "rbcd_principals": _as_list(raw.get("rbcd_principals")),
        "rbcd_principal_names": _as_list(raw.get("rbcd_principal_names")),
        "laps_attributes": _as_list(raw.get("laps_attributes")),
        "sid_history": _as_list(raw.get("sid_history")),
        "token_group_sids": _as_list(raw.get("token_group_sids")),
        "risk_factors": _as_list(raw.get("risk_factors")),
        "risk_controls": _as_list(raw.get("risk_controls")),
        "ipv4_addresses": _as_list(raw.get("ipv4_addresses")),
        "ipv6_addresses": _as_list(raw.get("ipv6_addresses")),
    }


def _member_record(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        member_dn = value.get("dn") or value.get("member_dn") or ""
        return {
            "member_name": value.get("name") or value.get("member_name") or _name_from_dn(member_dn),
            "member_sid": value.get("sid") or value.get("member_sid"),
            "member_dn": member_dn,
            "is_user": _as_bool(value.get("is_user")),
            "is_computer": _as_bool(value.get("is_computer")),
            "is_group": _as_bool(value.get("is_group")),
            "isaclprotected": _as_bool(value.get("isaclprotected")),
            "domainsid": value.get("domainsid") or _domain_sid_from_sid(value.get("sid") or value.get("member_sid")),
        }
    member_dn = str(value)
    name = _name_from_dn(member_dn)
    return {
        "member_name": name,
        "member_sid": None,
        "member_dn": member_dn,
        "is_user": ",CN=Users," in member_dn or ",OU=" in member_dn,
        "is_computer": False,
        "is_group": False,
        "isaclprotected": False,
        "domainsid": None,
    }


def _group_record(raw: dict[str, Any]) -> dict[str, Any]:
    sid = raw.get("sid")
    members = [_member_record(item) for item in _as_list(raw.get("members"))]
    return {
        "group_name": raw.get("name") or raw.get("group_name") or "",
        "group_dn": raw.get("dn") or raw.get("group_dn") or "",
        "group_sid": sid,
        "member_count": len(members),
        "member_users_count": sum(1 for member in members if member["is_user"]),
        "is_empty": not members,
        "primary_group_token": raw.get("primary_group_token"),
        "isaclprotected": _as_bool(raw.get("isaclprotected")),
        "domainsid": raw.get("domainsid") or _domain_sid_from_sid(sid),
        "is_privileged": _as_bool(raw.get("is_privileged")),
        "is_protected": _as_bool(raw.get("is_protected")),
        "is_nested": _as_bool(raw.get("is_nested")) or any(member["is_group"] for member in members),
        "managed_by": raw.get("managed_by"),
        "info": raw.get("info"),
        "group_type": raw.get("group_type"),
        "security_enabled": _as_bool(raw.get("security_enabled", True)),
        "admin_count": raw.get("admin_count", 0),
        "is_critical_system_object": _as_bool(raw.get("is_critical_system_object")),
        "member_of": _as_list(raw.get("member_of")),
        "rid": raw.get("rid"),
        "description": raw.get("description"),
        "when_created": raw.get("when_created"),
        "when_changed": raw.get("when_changed"),
        "members": members,
    }


def _gpo_record(raw: dict[str, Any]) -> dict[str, Any]:
    guid = raw.get("guid")
    return {
        "name": raw.get("name") or "",
        "guid": guid,
        "display_name": raw.get("display_name") or raw.get("name"),
        "description": raw.get("description"),
        "dn": raw.get("dn") or "",
        "path": raw.get("file_system_path") or raw.get("path"),
        "domain": raw.get("domain") or _domain_from_dn(raw.get("dn")),
        "domainsid": raw.get("domainsid"),
        "created": raw.get("created") or raw.get("when_created"),
        "modified": raw.get("modified") or raw.get("when_changed"),
        "version": raw.get("version") or 0,
        "user_version": raw.get("user_version") or 0,
        "computer_version": raw.get("computer_version") or 0,
        "flags": raw.get("flags") or 0,
        "user_settings_disabled": _as_bool(raw.get("user_settings_disabled")),
        "computer_settings_disabled": _as_bool(raw.get("computer_settings_disabled")),
        "is_critical_system_object": _as_bool(raw.get("is_critical_system_object")),
        "linked_count": len(_as_list(raw.get("linked_ous") or raw.get("linked_containers"))),
        "enforced": _as_bool(raw.get("enforced")),
        "link_disabled": _as_bool(raw.get("link_disabled")),
        "isaclprotected": _as_bool(raw.get("isaclprotected")),
        "owner_sid": raw.get("owner_sid"),
        "owner_name": raw.get("owner_name"),
        "highvalue": _as_bool(raw.get("highvalue")),
        "inheritance_blocked": _as_bool(raw.get("inheritance_blocked")),
        "linked_containers": _as_list(raw.get("linked_ous") or raw.get("linked_containers")),
        "user_extensions": _as_list(raw.get("user_extensions")),
        "machine_extensions": _as_list(raw.get("machine_extensions")),
        "risk_controls": _as_list(raw.get("risk_controls")),
        "all_cpasswords": _as_list(raw.get("all_cpasswords")),
        "ldap_dacl_aces": _as_list(raw.get("ldap_dacl_aces")),
        "ou_inheritance": _as_list(raw.get("ou_inheritance")),
        "sysvol": _as_list(raw.get("sysvol")),
    }


def _ou_record(raw: dict[str, Any]) -> dict[str, Any]:
    links = []
    for order, value in enumerate(_as_list(raw.get("gplink") or raw.get("linked_gpos")), start=1):
        gpo_dn = value.get("gpo_dn") if isinstance(value, dict) else str(value)
        links.append({
            "gpo_dn": gpo_dn,
            "gpo_guid": value.get("gpo_guid") if isinstance(value, dict) else None,
            "order": value.get("order", order) if isinstance(value, dict) else order,
            "enforced": _as_bool(value.get("enforced")) if isinstance(value, dict) else False,
            "link_enabled": _as_bool(value.get("link_enabled", True)) if isinstance(value, dict) else True,
        })
    return {
        "name": raw.get("name") or "",
        "dn": raw.get("dn") or "",
        "path": raw.get("path") or raw.get("dn") or "",
        "description": raw.get("description"),
        "managed_by": raw.get("managed_by"),
        "type": raw.get("type") or "organizationalUnit",
        "objectguid": raw.get("objectguid") or raw.get("object_guid"),
        "objectid": raw.get("objectid") or raw.get("object_guid"),
        "is_critical_system_object": _as_bool(raw.get("is_critical_system_object")),
        "parent_dn": raw.get("parent_dn") or _parent_dn_of(raw.get("dn")),
        "depth": raw.get("depth") if raw.get("depth") is not None else _ou_depth(raw.get("dn")),
        "gpo_links_raw": raw.get("gpo_links_raw") or ";".join(link["gpo_dn"] for link in links),
        "has_gpo_links": bool(links),
        "inheritance_blocked": _as_bool(raw.get("blocks_inheritance")) or _as_bool(raw.get("inheritance_blocked")),
        "blocksinheritance": _as_bool(raw.get("blocks_inheritance")) or _as_bool(raw.get("blocksinheritance")),
        "object_count": raw.get("object_count") or len(_as_list(raw.get("children"))),
        "is_protected": _as_bool(raw.get("is_protected")),
        "privileged_users_count": raw.get("privileged_users_count") or 0,
        "privileged_computers_count": raw.get("privileged_computers_count") or 0,
        "delegated_permissions": raw.get("delegated_permissions") or 0,
        "highvalue": _as_bool(raw.get("highvalue")),
        "isaclprotected": _as_bool(raw.get("isaclprotected")),
        "domainsid": raw.get("domainsid"),
        "created": raw.get("created") or raw.get("when_created"),
        "modified": raw.get("modified") or raw.get("when_changed"),
        "childous": _as_list(raw.get("child_ous") or raw.get("childous")),
        "risk_controls": _as_list(raw.get("risk_controls")),
        "linked_gpos": links,
        "gpo_precedence": _as_list(raw.get("gpo_precedence")),
        "inherited_gpos": _as_list(raw.get("inherited_gpos")),
        "privileged_users": _as_list(raw.get("privileged_users")),
        "privileged_computers": _as_list(raw.get("privileged_computers")),
    }


_ENCRYPTION_TYPE_NAMES = (
    (0x1, "DES-CBC-CRC"),
    (0x2, "DES-CBC-MD5"),
    (0x4, "RC4-HMAC"),
    (0x8, "AES128-CTS-HMAC-SHA1-96"),
    (0x10, "AES256-CTS-HMAC-SHA1-96"),
)


def _decode_encryption_types(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [name for bit, name in _ENCRYPTION_TYPE_NAMES if int(value) & bit]


def _trust_record(raw: dict[str, Any]) -> dict[str, Any]:
    direction = str(raw.get("trust_direction") or raw.get("direction") or "")
    forest_transitive = _as_bool(raw.get("forest_transitive")) or _as_bool(raw.get("forest"))
    return {
        "name": raw.get("target_domain") or raw.get("name") or "",
        "partner": raw.get("target_domain") or raw.get("partner") or "",
        "flat_name": raw.get("flat_name"),
        "sid": raw.get("sid") or raw.get("target_sid"),
        "dn": raw.get("dn") or "",
        "object_guid": raw.get("object_guid"),
        "description": raw.get("description"),
        "trust_type": raw.get("trust_type") or "",
        "trust_type_raw": raw.get("trust_type_raw"),
        "direction": direction,
        "direction_raw": raw.get("direction_raw") if raw.get("direction_raw") is not None else raw.get("trust_direction_raw"),
        "inbound": direction in {"inbound", "bidirectional"},
        "outbound": direction in {"outbound", "bidirectional"},
        "attributes_raw": raw.get("attributes_raw") or raw.get("trust_attributes") or 0,
        "transitive": _as_bool(raw.get("transitive")),
        "forest": forest_transitive,
        "within_forest": _as_bool(raw.get("within_forest")),
        "treat_as_external": _as_bool(raw.get("treat_as_external")),
        "sid_filtering_enabled": _as_bool(raw.get("sid_filtering", True)),
        "selective_auth": _as_bool(raw.get("selective_auth")),
        "forest_wide_auth": _as_bool(raw.get("forest_wide_auth")),
        "uses_rc4_encryption": _as_bool(raw.get("uses_rc4_encryption")),
        "uses_aes_keys": _as_bool(raw.get("uses_aes_keys")),
        "uplevel_only": _as_bool(raw.get("uplevel_only")),
        "pim_trust": _as_bool(raw.get("pim_trust")),
        "tgt_delegation_enabled": _as_bool(raw.get("tgt_delegation_enabled")),
        "dangerous": _as_bool(raw.get("dangerous")),
        "usn_created": raw.get("usn_created"),
        "usn_changed": raw.get("usn_changed"),
        "when_created": raw.get("when_created"),
        "when_changed": raw.get("when_changed"),
        "attributes_decoded": _as_list(raw.get("attributes_decoded")),
        "forest_trust_info": _as_list(raw.get("forest_trust_info")),
        "supported_encryption_types": _decode_encryption_types(raw.get("supported_encryption_types")),
        "risk_controls": _as_list(raw.get("risk_controls")),
        "security_posture": _as_list(raw.get("security_posture")),
    }


def _domain_info_record(raw: dict[str, Any]) -> dict[str, Any]:
    level_name = str(raw.get("functional_level") or "")
    policy = raw.get("password_policy") or {}
    security = raw.get("authentication_security") or {}
    return {
        "fqdn": raw.get("name") or raw.get("fqdn") or "",
        "netbios_name": str(raw.get("name") or "").split(".", 1)[0].upper(),
        "domain_sid": raw.get("sid") or raw.get("domain_sid"),
        "functional_level": _FUNCTIONAL_LEVELS.get(level_name, raw.get("functional_level")),
        "functional_level_name": level_name,
        "smb_signing_policy_present": raw.get("smb_signing_required") is not None,
        "smb_signing_enabled": raw.get("smb_signing_required"),
        "smb_signing_required": raw.get("smb_signing_required"),
        "ntlm_supported": security.get("ntlm_status"),
        "kerberos_status": security.get("kerberos_status"),
        "ldap_signing": security.get("ldap_signing"),
        "authentication_security": security,
        "smart_card_required": False,
        "machine_account_quota": 10,
        "risk_score": 0,
        "highest_severity": "info",
        "fine_grained_policies": [],
        "has_enterprise_ca": False,
        "ca_list": [],
        "dns_zones": _as_list(raw.get("dns_zones")),
        "domain_controllers": _as_list(raw.get("domain_controllers")),
        "risk_findings": [],
        "fsmo": raw.get("fsmo_roles") or {},
        "laps": raw.get("laps") or {},
        "null_anonymous_access": raw.get("null_anonymous_access") or {},
        "password_policy": {
            "min_length": policy.get("min_pwd_length"),
            "complexity_enabled": policy.get("complexity_enabled"),
            "max_age_days": policy.get("max_age_days"),
            "min_age_days": policy.get("min_age_days"),
            "history_count": policy.get("pwd_history_length"),
            "lockout_threshold": policy.get("lockout_threshold"),
            "lockout_duration_mins": policy.get("lockout_duration"),
            "lockout_observation_mins": policy.get("lockout_observation_window"),
            "reversible_encryption": bool(policy.get("pwd_properties", 0) & 0x10),
            "pwd_properties_raw": policy.get("pwd_properties"),
        },
        "kerberos_policy": {},
    }


def canonicalize(name: str, record: Any) -> dict[str, Any]:
    raw = _record_dict(record)
    converters = {
        "users": _user_record,
        "computers": _computer_record,
        "groups": _group_record,
        "gpos": _gpo_record,
        "ous": _ou_record,
        "trusts": _trust_record,
        "domains": _domain_info_record,
        "domain_info": _domain_info_record,
    }
    try:
        return converters.get(name, lambda value: value)(raw)
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError(f"Cannot normalize {name} JSONL record: {exc}") from exc


class JSONLBackend:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(self, name: str, records: list[Any]) -> Path:
        from modules.aces.snapshots import _write_acl_jsonl_snapshot

        if name == "domains":
            filename = "domain_info.jsonl"
        elif name in RAW_MODULES:
            # Collector output only; the engine derives domain_<name>.jsonl from it.
            filename = f"raw_{name}.jsonl"
        else:
            filename = f"domain_{name}.jsonl"
        path = self.output_dir / filename

        result = getattr(records, "result", None) or {}
        normalized_records = [canonicalize(name, record) for record in records]

        meta_line = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "local" if result.get("is_local") else "domain",
            "success": bool(result.get("success", True)),
            "count": int(result.get("count") or len(normalized_records)),
            "error": result.get("error") if not result.get("success", True) else None,
            "meta": result.get("meta") or {},
        }

        _write_acl_jsonl_snapshot(path, meta_line, normalized_records)
        return path

    def write_all(self, results: dict[str, list[Any]]) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        for name, records in results.items():
            if name == "aces":
                paths.update(self._write_acl_snapshots(records))
            else:
                paths[name] = self.write(name, records)
        return paths

    def _write_acl_snapshots(self, records: list[Any]) -> dict[str, Path]:
        from modules.aces.snapshots import write_acl_snapshots

        result = getattr(records, "result", None)
        if result is None and not records:
            return {}
        if result is None:
            result = {"success": True, "count": len(records), "acls": list(records), "meta": {}}
        return write_acl_snapshots(result, self.output_dir)