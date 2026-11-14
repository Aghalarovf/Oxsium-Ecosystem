from __future__ import annotations

import re

NTLM_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
_EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


def is_ntlm_hash(value: str | None) -> bool:
    return bool(value) and bool(NTLM_HASH_RE.match(value))


def build_ntlm_user(domain: str, username: str) -> str:
    return f"{domain}\\{username}"


def resolve_secret(credentials) -> str:
    if credentials.nt_hash:
        return f"{_EMPTY_LM_HASH}:{credentials.nt_hash}"
    return credentials.password or ""
