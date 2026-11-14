from __future__ import annotations

import json
from pathlib import Path

_DIR = Path(__file__).resolve().parent


def _load(filename: str) -> dict:
    with open(_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


def _int(value: str | int) -> int:
    return int(value, 16) if isinstance(value, str) else value


def _ints(table: dict) -> dict[str, int]:
    return {name: _int(value) for name, value in table.items()}


_C = _load("constants.json")
_G = _load("guids.json")

_M = _ints(_C["access_masks"])
GENERIC_ALL_RAW        = _M["GENERIC_ALL_RAW"]
GENERIC_ALL_COMPOSED   = _M["GENERIC_ALL_COMPOSED"]
RAW_GENERIC_WRITE      = _M["RAW_GENERIC_WRITE"]
GENERIC_WRITE_COMPOSED = _M["GENERIC_WRITE_COMPOSED"]
SELF_BIT               = _M["SELF_BIT"]
WRITE_PROPERTY_BIT     = _M["WRITE_PROPERTY_BIT"]
READ_PROPERTY_BIT      = _M["READ_PROPERTY_BIT"]
CONTROL_ACCESS_RIGHT   = _M["CONTROL_ACCESS_RIGHT"]

INDIVIDUAL_RIGHTS: dict[str, int] = _ints(_C["individual_rights"])
CA_SECURITY_RIGHTS: dict[str, int] = _ints(_C["ca_security_rights"])

_F = _ints(_C["ace_flags"])
ACE_FLAG_INHERITED         = _F["ACE_FLAG_INHERITED"]
ACE_FLAG_CONTAINER_INHERIT = _F["ACE_FLAG_CONTAINER_INHERIT"]
ACE_FLAG_OBJECT_INHERIT    = _F["ACE_FLAG_OBJECT_INHERIT"]
ACE_FLAG_INHERIT_ONLY      = _F["ACE_FLAG_INHERIT_ONLY"]

_T = _ints(_C["ace_types"])
ACE_TYPE_ALLOWED        = _T["ACE_TYPE_ALLOWED"]
ACE_TYPE_DENIED         = _T["ACE_TYPE_DENIED"]
ACE_TYPE_ALLOWED_OBJECT = _T["ACE_TYPE_ALLOWED_OBJECT"]
ACE_TYPE_DENIED_OBJECT  = _T["ACE_TYPE_DENIED_OBJECT"]
_ALLOWED_ACE_TYPES      = frozenset({ACE_TYPE_ALLOWED, ACE_TYPE_ALLOWED_OBJECT})

OBJECT_TYPE_RIGHTS: dict[str, str] = _G["aces_guid"]
DANGEROUS_ACES_GUID: dict[str, str] = _G["dangerous_aces_guid"]
EXTENDED_RIGHTS_GUID: dict[str, str] = _G["extended_rights_guid"]
DANGEROUS_EXTENDED_RIGHTS_GUID: dict[str, str] = _G["dangerous_extended_rights_guid"]

_R = _C["rights"]
EXTENDED_RIGHT_NAMES         = frozenset(_G["extended_right_names"])
DANGEROUS_RIGHTS             = frozenset(_R["dangerous_rights"])
CA_SECURITY_DANGEROUS_RIGHTS = frozenset(_R["ca_security_dangerous_rights"])
_TOMBSTONE_REANIMATE_RIGHTS  = frozenset(_R["tombstone_reanimate_rights"])
_TOMBSTONE_VISIBILITY_RIGHTS = frozenset(_R["tombstone_visibility_rights"])
_TEMPLATE_CRITICAL_RIGHTS    = frozenset(_R["template_critical_rights"])

INTERESTING_RIGHTS = frozenset(
    set(_R["interesting_rights_extra"])
    | set(INDIVIDUAL_RIGHTS)
    | set(OBJECT_TYPE_RIGHTS.values())
)

ACE_RIGHT_NAMES = frozenset(
    set(INDIVIDUAL_RIGHTS)
    | set(OBJECT_TYPE_RIGHTS.values())
    | set(_R["ace_right_names_extra"])
)

ACE_RIGHT_FLAGS: dict[str, tuple[bool, bool]] = {
    name: (
        name in DANGEROUS_RIGHTS,
        name in DANGEROUS_RIGHTS and name in EXTENDED_RIGHT_NAMES,
    )
    for name in ACE_RIGHT_NAMES
}

WELL_KNOWN_SIDS: dict[str, str] = _C["well_known_sids"]

_TR = _C["trustees"]
_PRIVILEGED_RIDS             = frozenset(_TR["privileged_rids"])
_BROAD_RIDS                  = frozenset(_TR["broad_rids"])
_BROAD_SIDS                  = frozenset(_TR["broad_sids"])
_DEFAULT_TRUSTEE_SIDS        = frozenset(_TR["default_trustee_sids"])
_DEFAULT_TRUSTEE_RIDS        = frozenset(_TR["default_trustee_rids"])
_DANGEROUS_ACE_NOISY_NAMES: frozenset[str]   = frozenset(_TR["dangerous_ace_noisy_names"])
_DANGEROUS_ACE_NOISY_RIDS: frozenset[str]    = frozenset(_TR["dangerous_ace_noisy_rids"])
_EXTENDED_RIGHTS_NOISY_NAMES: frozenset[str] = frozenset(_TR["extended_rights_noisy_names"])
_EXTENDED_RIGHTS_NOISY_RIDS: frozenset[str]  = frozenset(_TR["extended_rights_noisy_rids"])

_L = _C["ldap"]
_PAGED_CTRL_OID              = _L["paged_ctrl_oid"]
LDAP_SERVER_SHOW_DELETED_OID = _L["show_deleted_oid"]
_SD_FLAGS                    = _int(_L["sd_flags"])
_SD_FLAGS_FULL               = _int(_L["sd_flags_full"])
TARGET_FILTER                = _L["target_filter"]

AD_OBJECT_TYPE_MAP: dict[str, str] = _C["ad_object_type_map"]

_AD_SENSITIVE_TEMPLATES: dict[str, tuple[str, str]] = {
    name: (item["dn"], item["description"])
    for name, item in _C["sensitive_templates"].items()
}

_DS = _C["deep_scan"]
_DEEP_SCAN_BASES: tuple[str, ...]         = tuple(_DS["bases"])
_DEEP_SCAN_BASES_MINIMAL: tuple[str, ...] = tuple(_DS["bases_minimal"])
_DEEP_SCAN_CRITICAL_SUBTREES: tuple[tuple[str, str], ...] = tuple(
    (item["dn"], item["description"]) for item in _DS["critical_subtrees"]
)