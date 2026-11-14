from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AuthMethod(Enum):
    PASSWORD = auto()
    NTLM_HASH = auto()
    KERBEROS_CCACHE = auto()


@dataclass
class Credentials:
    domain: str
    username: str = ""
    password: str | None = None
    nt_hash: str | None = None
    ccache_path: str | None = None

    @property
    def auth_method(self) -> AuthMethod:
        if self.ccache_path:
            return AuthMethod.KERBEROS_CCACHE
        if self.nt_hash:
            return AuthMethod.NTLM_HASH
        return AuthMethod.PASSWORD


class Session:
    def __init__(
        self,
        target: str,
        credentials: Credentials,
        dc_host: str | None = None,
        use_ssl: bool = False,
        enumerate_ip: bool = False,
    ):
        self.target = target
        self.enumerate_ip = enumerate_ip
        self.credentials = credentials
        self.dc_host = dc_host
        self.use_ssl = use_ssl
        self.domain_sid: str | None = None
        self._ldap = None
        self._base_dn: str | None = None

    def ldap(self):
        if self._ldap is None:
            from core.ldap.connection import LDAPConnection

            self._ldap = LDAPConnection(self.target, use_ssl=self.use_ssl, dc_host=self.dc_host)
            self._ldap.bind(self.credentials)
            self._base_dn = self._ldap.base_dn
        return self._ldap

    @property
    def base_dn(self) -> str | None:
        if self._base_dn is None:
            self.ldap()
        return self._base_dn

    def close(self) -> None:
        if self._ldap is not None:
            self._ldap.unbind()