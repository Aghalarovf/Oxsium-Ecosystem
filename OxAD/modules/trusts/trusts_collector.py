from __future__ import annotations

import logging
import struct

from core.models import ADTrust
from core.session import Session
from modules.base import BaseModule, ModuleResult
from utils.adutils import entry_guid, ldap_generalized_time_to_iso, normalize_value, safe_int
from utils.sid_utils import sid_bytes_to_str

logger = logging.getLogger(__name__)

_TRUST_ATTRS = [
    "distinguishedName",
    "objectGUID",
    "description",
    "trustPartner",
    "trustDirection",
    "trustType",
    "trustAttributes",
    "securityIdentifier",
    "flatName",
    "uSNCreated",
    "uSNChanged",
    "msDS-SupportedEncryptionTypes",
    "msDS-TrustForestTrustInfo",
    "whenCreated",
    "whenChanged",
]

_TRUST_DIRECTIONS = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
_TRUST_TYPES = {1: "downlevel", 2: "uplevel", 3: "mit", 4: "dce"}

_NON_TRANSITIVE = 0x1
_UPLEVEL_ONLY = 0x2
_QUARANTINED_DOMAIN = 0x4
_FOREST_TRANSITIVE = 0x8
_CROSS_ORGANIZATION = 0x10
_WITHIN_FOREST = 0x20
_TREAT_AS_EXTERNAL = 0x40
_USES_RC4_ENCRYPTION = 0x80
_USES_AES_KEYS = 0x100
_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x200
_PIM_TRUST = 0x400
_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x800

_ATTRIBUTE_NAMES = (
    (_NON_TRANSITIVE, "NON_TRANSITIVE"),
    (_UPLEVEL_ONLY, "UPLEVEL_ONLY"),
    (_QUARANTINED_DOMAIN, "QUARANTINED_DOMAIN"),
    (_FOREST_TRANSITIVE, "FOREST_TRANSITIVE"),
    (_CROSS_ORGANIZATION, "CROSS_ORGANIZATION"),
    (_WITHIN_FOREST, "WITHIN_FOREST"),
    (_TREAT_AS_EXTERNAL, "TREAT_AS_EXTERNAL"),
    (_USES_RC4_ENCRYPTION, "USES_RC4_ENCRYPTION"),
    (_USES_AES_KEYS, "USES_AES_KEYS"),
    (_CROSS_ORGANIZATION_NO_TGT_DELEGATION, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
    (_PIM_TRUST, "PIM_TRUST"),
    (_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"),
)

_FOREST_TRUST_RECORD_TYPES = {0: "top_level_name", 1: "top_level_name_ex", 2: "domain_info"}


def _decode_attributes(attributes: int) -> list[str]:
    return [name for bit, name in _ATTRIBUTE_NAMES if attributes & bit]


def _read_counted(payload: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack_from("<I", payload, offset)
    start = offset + 4
    return payload[start:start + length], start + length


def _parse_forest_trust_info(data) -> list[dict]:
    if not data or len(data) < 8:
        return []

    records: list[dict] = []
    try:
        _version, count = struct.unpack_from("<II", data, 0)
        offset = 8
        for _ in range(count):
            (record_len,) = struct.unpack_from("<I", data, offset)
            body = bytes(data[offset + 4:offset + 4 + record_len])
            flags, _timestamp, record_type = struct.unpack_from("<IQB", body, 0)
            payload = body[13:]
            record = {
                "type": _FOREST_TRUST_RECORD_TYPES.get(record_type, str(record_type)),
                "flags": flags,
            }

            if record_type in (0, 1):
                name, _ = _read_counted(payload, 0)
                record["name"] = name.decode("utf-8", errors="replace")
            elif record_type == 2:
                sid, pos = _read_counted(payload, 0)
                dns_name, pos = _read_counted(payload, pos)
                netbios_name, _ = _read_counted(payload, pos)
                record["sid"] = sid_bytes_to_str(sid) if sid else None
                record["dns_name"] = dns_name.decode("utf-8", errors="replace")
                record["netbios_name"] = netbios_name.decode("utf-8", errors="replace")

            records.append(record)
            offset += 4 + record_len
    except (struct.error, ValueError, IndexError):
        logger.warning("forest trust info could not be fully parsed")

    return records


def _risk_and_posture(
    attributes: int, direction: str, within_forest: bool, forest_transitive: bool
) -> tuple[list[str], list[str], bool]:
    risks: list[str] = []
    posture: list[str] = []
    dangerous = False

    selective = bool(attributes & _CROSS_ORGANIZATION)
    quarantined = bool(attributes & _QUARANTINED_DOMAIN)
    external = not within_forest and not forest_transitive

    if external and not quarantined:
        risks.append("sid_filtering_disabled")
        dangerous = True
    if quarantined:
        posture.append("sid_filtering")

    if attributes & _CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION:
        risks.append("tgt_delegation_enabled")
        dangerous = True

    if attributes & _USES_RC4_ENCRYPTION and not attributes & _USES_AES_KEYS:
        risks.append("rc4_encryption")
    if attributes & _USES_AES_KEYS:
        posture.append("aes_keys")

    if not within_forest and direction != "disabled":
        if selective:
            posture.append("selective_authentication")
        else:
            risks.append("forest_wide_authentication")

    return risks, posture, dangerous


class TrustsModule(BaseModule):
    name = "trusts"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            entries = ldap.search(session.base_dn, "(objectClass=trustedDomain)", _TRUST_ATTRS)
        except Exception as exc:
            logger.warning("trusts collector failed: %s", exc)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})

        trusts: list[ADTrust] = []

        for entry in entries:
            direction_raw = safe_int(normalize_value(entry["trustDirection"].value))
            type_raw = safe_int(normalize_value(entry["trustType"].value))
            attributes = safe_int(normalize_value(entry["trustAttributes"].value))
            direction = _TRUST_DIRECTIONS.get(direction_raw, str(direction_raw))

            sid_raw = entry["securityIdentifier"].raw_values
            target_sid = sid_bytes_to_str(sid_raw[0]) if sid_raw else None

            fti_raw = entry["msDS-TrustForestTrustInfo"].raw_values
            forest_trust_info = _parse_forest_trust_info(fti_raw[0]) if fti_raw else []

            enc_value = normalize_value(entry["msDS-SupportedEncryptionTypes"].value)
            supported_enc = safe_int(enc_value) if enc_value is not None else None

            within_forest = bool(attributes & _WITHIN_FOREST)
            forest_transitive = bool(attributes & _FOREST_TRANSITIVE)
            selective = bool(attributes & _CROSS_ORGANIZATION)
            risks, posture, dangerous = _risk_and_posture(attributes, direction, within_forest, forest_transitive)

            usn_created = normalize_value(entry["uSNCreated"].value)
            usn_changed = normalize_value(entry["uSNChanged"].value)

            trusts.append(
                ADTrust(
                    dn=str(entry["distinguishedName"].value),
                    source_domain=session.credentials.domain,
                    target_domain=str(normalize_value(entry["trustPartner"].value)),
                    trust_direction=direction,
                    trust_type=_TRUST_TYPES.get(type_raw, str(type_raw)),
                    sid_filtering=bool(attributes & _QUARANTINED_DOMAIN),
                    transitive=not bool(attributes & _NON_TRANSITIVE),
                    target_sid=target_sid,
                    flat_name=normalize_value(entry["flatName"].value),
                    when_created=ldap_generalized_time_to_iso(normalize_value(entry["whenCreated"].value)),
                    when_changed=ldap_generalized_time_to_iso(normalize_value(entry["whenChanged"].value)),
                    forest_transitive=forest_transitive,
                    within_forest=within_forest,
                    uses_rc4_encryption=bool(attributes & _USES_RC4_ENCRYPTION),
                    trust_attributes=attributes,
                    object_guid=entry_guid(entry),
                    description=normalize_value(entry["description"].value),
                    trust_direction_raw=direction_raw,
                    trust_type_raw=type_raw,
                    selective_auth=selective,
                    forest_wide_auth=not selective,
                    treat_as_external=bool(attributes & _TREAT_AS_EXTERNAL),
                    uplevel_only=bool(attributes & _UPLEVEL_ONLY),
                    uses_aes_keys=bool(attributes & _USES_AES_KEYS),
                    pim_trust=bool(attributes & _PIM_TRUST),
                    tgt_delegation_enabled=bool(attributes & _CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION),
                    usn_created=safe_int(usn_created) if usn_created is not None else None,
                    usn_changed=safe_int(usn_changed) if usn_changed is not None else None,
                    supported_encryption_types=supported_enc,
                    attributes_decoded=_decode_attributes(attributes),
                    forest_trust_info=forest_trust_info,
                    risk_controls=risks,
                    security_posture=posture,
                    dangerous=dangerous,
                )
            )

        result = {"success": True, "count": len(trusts), "error": None, "meta": {}}
        return ModuleResult(trusts, result)