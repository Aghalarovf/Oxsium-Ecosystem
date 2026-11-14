import traceback
from collections.abc import Callable
from typing import Optional

from core.config import Config

from .backends import (
    ImpacketParser,
    Ldap3Backend,
    make_conn_factory,
)
from .collector import AclCollector
from .models import AclFilterConfig, LdapConfig, ObjectScope
from .parsers import _build_guid_map


def _capture_error(stage: str, context: str, exc: BaseException) -> dict:
    return {
        "stage":         stage,
        "context":       context,
        "error_type":    type(exc).__name__,
        "error_message": str(exc),
        "traceback":     traceback.format_exc(limit=20),
    }


def get_domain_acls(
    session,
    acl_filter: Optional[AclFilterConfig] = None,
    scope: ObjectScope = ObjectScope.DEEP_SCAN,
    custom_filter: str = "",
    resolve_guids: bool = False,
    on_records: Optional[Callable[[list[dict]], None]] = None,
    sequential: bool = False,
    deep_scan_minimal: bool = False,
    io_workers: Optional[int] = None,
) -> dict:
    """Same flow as the framework's Main/acl/api.py:get_domain_acls.

    The connection comes from the OxAD session (already bound with the chosen
    auth method) instead of ip/username/password parameters.
    """
    flt      = acl_filter or AclFilterConfig()
    ldap_cfg = LdapConfig.from_app_config(Config)

    try:
        parser = ImpacketParser()
    except ImportError as e:
        err = _capture_error("init_parser", "ImpacketParser", e)
        return {"success": False, "error": str(e), "code": 500,
                "meta": {"error_count": 1, "errors": [err]}}

    backend = None
    try:
        from ldap3.core.exceptions import (
            LDAPInvalidCredentialsResult,
            LDAPSocketOpenError,
        )
        base_dn = session.base_dn
        if not base_dn:
            raise ValueError("Base DN could not be determined from the LDAP session")
        backend = Ldap3Backend.from_session(session)
    except LDAPInvalidCredentialsResult as e:
        err = _capture_error("ldap_bind", f"{session.target} user={session.credentials.username}", e)
        return {"success": False, "error": "Authentication failed", "code": 401,
                "meta": {"error_count": 1, "errors": [err]}}
    except LDAPSocketOpenError as e:
        err = _capture_error("ldap_connect", session.target, e)
        return {"success": False, "error": "Cannot connect to LDAP server", "code": 503,
                "meta": {"error_count": 1, "errors": [err]}}
    except Exception as e:
        err = _capture_error("ldap_bind", f"{session.target} user={session.credentials.username}", e)
        return {"success": False, "error": str(e), "code": 500,
                "meta": {"error_count": 1, "errors": [err]}}

    pre_errors: list[dict] = []
    try:
        _guid_map = None
        if resolve_guids:
            try:
                _guid_map = _build_guid_map(backend, base_dn, page_size=ldap_cfg.page_size)
            except Exception as e:
                _guid_map = None
                pre_errors.append(_capture_error("build_guid_map", base_dn, e))

        conn_factory = None if sequential else make_conn_factory(session)

        collector = AclCollector(
            backend, base_dn, parser,
            page_size=ldap_cfg.page_size,
            guid_map=_guid_map,
            conn_factory=conn_factory,
            initial_errors=pre_errors,
            io_workers=io_workers if io_workers is not None else 2,
            deep_scan_minimal=deep_scan_minimal,
        )
        return collector.collect(
            flt, scope=scope, custom_filter=custom_filter, on_records=on_records,
        )
    except Exception as e:
        err = _capture_error("get_domain_acls_internal", base_dn, e)
        errors = pre_errors + [err]
        return {"success": False, "error": f"Internal error: {e}", "code": 500,
                "meta": {"error_count": len(errors), "errors": errors}}
