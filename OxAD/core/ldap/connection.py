from __future__ import annotations

from ldap3 import ALL, GSSAPI, NTLM, SASL, Connection, Server

from core.config import Config
from core.ldap.paging import paged_search
from core.session import AuthMethod


class LDAPConnection:
    def __init__(self, host: str, use_ssl: bool = False, port: int | None = None, dc_host: str | None = None):
        self.host = host
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.dc_host = dc_host
        self.server = Server(host, port=self.port, use_ssl=use_ssl, get_info=ALL, connect_timeout=Config.LDAP_CONNECT_TIMEOUT)
        self.conn: Connection | None = None
        self.base_dn: str | None = None

    def bind(self, credentials):
        if credentials.auth_method == AuthMethod.KERBEROS_CCACHE:
            self._bind_kerberos(credentials)
        else:
            self._bind_ntlm(credentials)

        naming_contexts = self.server.info.other.get("defaultNamingContext")
        self.base_dn = naming_contexts[0] if naming_contexts else None
        return self

    def _bind_ntlm(self, credentials) -> None:
        from core.ntlm.auth import build_ntlm_user, resolve_secret

        user = build_ntlm_user(credentials.domain, credentials.username)
        secret = resolve_secret(credentials)

        self.conn = Connection(
            self.server,
            user=user,
            password=secret,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
        )

    def _bind_kerberos(self, credentials) -> None:
        from core.kerberos.gssapi import prepare_ccache_env

        prepare_ccache_env(credentials.ccache_path)
        sasl_credentials = (None, None, self.dc_host, None, None)

        self.conn = Connection(
            self.server,
            authentication=SASL,
            sasl_mechanism=GSSAPI,
            sasl_credentials=sasl_credentials,
            auto_bind=True,
            receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
        )

    def search(self, base_dn, ldap_filter, attributes, scope="SUBTREE", controls=None):
        from ldap3 import BASE, LEVEL, SUBTREE as _SUBTREE

        scope_map = {"BASE": BASE, "LEVEL": LEVEL, "SUBTREE": _SUBTREE}
        resolved_scope = scope_map.get(scope, scope) if isinstance(scope, str) else scope

        return paged_search(
            self.conn,
            base_dn or self.base_dn,
            ldap_filter,
            attributes,
            scope=resolved_scope,
            controls=controls,
            page_size=Config.LDAP_PAGE_SIZE,
        )

    def unbind(self) -> None:
        if self.conn:
            self.conn.unbind()
