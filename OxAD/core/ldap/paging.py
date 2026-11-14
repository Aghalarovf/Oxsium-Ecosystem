from __future__ import annotations

from ldap3 import SUBTREE

_PAGED_CTRL_OID = "1.2.840.113556.1.4.319"


def paged_search(conn, base_dn, ldap_filter, attributes, scope=SUBTREE, controls=None, page_size=500):
    entries = []
    cookie = True

    while cookie:
        conn.search(
            search_base=base_dn,
            search_filter=ldap_filter,
            search_scope=scope,
            attributes=attributes,
            controls=controls,
            paged_size=page_size,
            paged_cookie=cookie if cookie is not True else None,
        )
        entries.extend(conn.entries)

        control = conn.result.get("controls", {}).get(_PAGED_CTRL_OID, {})
        cookie = control.get("value", {}).get("cookie")
        if not cookie:
            break

    return entries
