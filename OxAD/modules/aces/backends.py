import random
import re
import time
from datetime import datetime, timezone

from .models import LdapConfig, LdapBackend, SecurityDescriptorParser  # noqa: F401


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def domain_to_dn(domain: str) -> str:
    if not domain or not domain.strip():
        raise ValueError(f"Invalid domain value: {domain!r}")
    return ",".join(f"DC={p}" for p in domain.strip().split("."))


def get_bind_user(username: str, domain: str, auth_type: str = "SIMPLE") -> str:
    if "@" in username or "\\" in username:
        return username
    # NTLM bind DOMAIN\\username formatini teleb edir, UPN (user@domain) deyil
    if auth_type == "NTLM":
        domain_short = domain.split(".")[0].upper()
        return f"{domain_short}\\{username}"
    return f"{username}@{domain}"


def normalize_value(value):
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, list):
        return value[0] if value else None
    return value


def ldap_ts_to_iso(value) -> str | None:
    v = normalize_value(value)
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.replace(tzinfo=v.tzinfo or timezone.utc).isoformat()
    try:
        ticks = int(str(v))
    except (ValueError, TypeError):
        return str(v)
    if ticks in (0, 9_223_372_036_854_775_807):
        return None
    try:
        return datetime.fromtimestamp(
            (ticks - 116_444_736_000_000_000) / 10_000_000, tz=timezone.utc
        ).isoformat()
    except (OSError, OverflowError, ValueError):
        return str(v)


_RETRYABLE_EXCEPTIONS_CACHE: tuple[type[BaseException], ...] | None = None


def _get_retryable_exceptions() -> tuple[type[BaseException], ...]:
    global _RETRYABLE_EXCEPTIONS_CACHE
    if _RETRYABLE_EXCEPTIONS_CACHE is not None:
        return _RETRYABLE_EXCEPTIONS_CACHE

    exceptions: list[type[BaseException]] = [ConnectionError, TimeoutError, OSError]
    try:
        from ldap3.core.exceptions import (
            LDAPSocketOpenError,
            LDAPSocketSendError,
            LDAPSocketReceiveError,
            LDAPTimeoutError,
        )
        exceptions = [
            LDAPSocketOpenError, LDAPSocketSendError,
            LDAPSocketReceiveError, LDAPTimeoutError,
            *exceptions,
        ]
    except ImportError:
        pass

    _RETRYABLE_EXCEPTIONS_CACHE = tuple(exceptions)
    return _RETRYABLE_EXCEPTIONS_CACHE


def search_with_retry(
    conn: "LdapBackend",
    base: str,
    ldap_filter: str,
    max_retries: int = 1,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    **kwargs,
) -> None:
    retryable = _get_retryable_exceptions()
    attempt = 0
    while True:
        try:
            conn.search(base, ldap_filter, **kwargs)
            return
        except retryable:
            attempt += 1
            if attempt > max_retries:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay += random.uniform(0, delay * 0.25)
            time.sleep(delay)


class ImpacketParser:
    def __init__(self) -> None:
        try:
            from impacket.ldap.ldaptypes import (
                ACCESS_ALLOWED_OBJECT_ACE,
                SR_SECURITY_DESCRIPTOR,
            )
            self._SR_SD   = SR_SECURITY_DESCRIPTOR
            self._OBJ_ACE = ACCESS_ALLOWED_OBJECT_ACE
        except ImportError as e:
            raise ImportError(f"impacket not installed: {e}") from e

    def parse(self, raw_sd: bytes) -> object:
        return self._SR_SD(data=raw_sd)["Dacl"]

    def is_object_ace(self, ace_data: object) -> bool:
        return isinstance(ace_data, self._OBJ_ACE)


class Ldap3Backend:
    """LdapBackend adapter over an already-bound ldap3 Connection.

    OxAD opens and authenticates every connection through core.ldap.LDAPConnection
    (NTLM / hash / Kerberos ccache), so unlike the framework version this class
    never binds by itself: it only wraps a bound connection.
    """

    def __init__(self, _conn=None) -> None:
        if _conn is None:
            raise ValueError("Ldap3Backend requires a bound ldap3 connection")
        self._conn = _conn

    @classmethod
    def from_connection(cls, conn) -> "Ldap3Backend":
        return cls(_conn=conn)

    @classmethod
    def from_session(cls, session) -> "Ldap3Backend":
        return cls(_conn=session.ldap().conn)

    def search(self, base: str, ldap_filter: str, **kwargs) -> None:
        self._conn.search(base, ldap_filter, **kwargs)

    @property
    def entries(self) -> list:
        return self._conn.entries

    @property
    def result(self) -> dict | None:
        return self._conn.result

    def unbind(self) -> None:
        self._conn.unbind()


def make_conn_factory(session):
    """Return a zero-argument callable that opens a fresh, bound Ldap3Backend.

    Each parallel ACL worker calls factory() to get its own connection. The
    connection is created through OxAD's LDAPConnection with the session's
    credentials, so every auth method OxAD supports works in the workers too.
    """
    def factory() -> Ldap3Backend:
        from core.ldap.connection import LDAPConnection

        ldap = LDAPConnection(session.target, use_ssl=session.use_ssl, dc_host=session.dc_host)
        ldap.bind(session.credentials)
        return Ldap3Backend(_conn=ldap.conn)
    return factory
