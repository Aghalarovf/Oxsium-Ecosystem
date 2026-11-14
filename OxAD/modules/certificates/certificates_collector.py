from __future__ import annotations

import base64
import logging
from typing import Any

from core.session import Session
from modules.base import BaseModule, ModuleResult
from utils.adutils import normalize_value

logger = logging.getLogger(__name__)

_TEMPLATE_ATTRIBUTES = ["*", "nTSecurityDescriptor"]

_PKI_ATTRIBUTES = ["*", "nTSecurityDescriptor"]

_OID_ATTRIBUTES = ["*", "nTSecurityDescriptor"]


def _safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe(item) for key, item in value.items()}
    return value


def _attributes(entry, names: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in names:
        try:
            attribute = entry[name]
            value = attribute.value
        except (KeyError, AttributeError):
            continue
        result[name] = _safe(value)
    return result


def _attributes_dynamic(entry) -> dict[str, Any]:
    return _attributes(entry, list(entry.entry_attributes))


def _record(record_type: str, entry) -> dict[str, Any]:
    dn = str(normalize_value(entry["distinguishedName"].value))
    values = _attributes_dynamic(entry)
    return {
        "record_type": record_type,
        "dn": dn,
        "name": values.get("name") or values.get("cn") or values.get("displayName"),
        "raw": values,
    }


class CertificatesModule(BaseModule):
    name = "cert"

    def run(self, session: Session) -> ModuleResult:
        try:
            ldap = session.ldap()
            configuration_dn = (ldap.server.info.other.get("configurationNamingContext") or [None])[0]
            if not configuration_dn:
                raise ValueError("configurationNamingContext was not returned by the LDAP server")
            pki_root = f"CN=Public Key Services,CN=Services,{configuration_dn}"
            records: list[dict] = []
            records.extend(
                _record("template", entry)
                for entry in ldap.search(
                    f"CN=Certificate Templates,{pki_root}",
                    "(objectClass=pKICertificateTemplate)",
                    _TEMPLATE_ATTRIBUTES,
                )
            )
            for label, relative_dn, ldap_filter, scope in (
                ("enrollment_service", f"CN=Enrollment Services,{pki_root}", "(objectClass=pKIEnrollmentService)", "LEVEL"),
                ("certification_authority", f"CN=Certification Authorities,{pki_root}", "(objectClass=certificationAuthority)", "LEVEL"),
                ("ntauth", f"CN=NTAuthCertificates,{pki_root}", "(objectClass=certificationAuthority)", "BASE"),
            ):
                records.extend(
                    _record(label, entry)
                    for entry in ldap.search(relative_dn, ldap_filter, _PKI_ATTRIBUTES, scope=scope)
                )
            records.extend(
                _record("oid", entry)
                for entry in ldap.search(
                    pki_root,
                    "(objectClass=msPKI-Enterprise-Oid)",
                    _OID_ATTRIBUTES,
                )
            )
            records.extend(self._collect_user_mappings(ldap, session.base_dn))
        except Exception as exc:
            logger.warning("certificate collector failed: %s", exc)
            logger.debug("certificate collector traceback", exc_info=True)
            return ModuleResult([], {"success": False, "count": 0, "error": str(exc), "meta": {}})
        result = {
            "success": True,
            "count": len(records),
            "error": None,
            "meta": {"configuration_dn": configuration_dn},
        }
        return ModuleResult(records, result)

    @staticmethod
    def _collect_user_mappings(ldap, base_dn: str | None) -> list[dict]:
        records = []
        for entry in ldap.search(
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(altSecurityIdentities=*))",
            ["distinguishedName", "sAMAccountName", "altSecurityIdentities"],
        ):
            values = _attributes(entry, ["distinguishedName", "sAMAccountName", "altSecurityIdentities"])
            records.append({
                "record_type": "user_mapping",
                "dn": values.get("distinguishedName"),
                "name": values.get("sAMAccountName"),
                "raw": values,
            })
        return records