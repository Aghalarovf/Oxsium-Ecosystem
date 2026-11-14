from __future__ import annotations

import os


def prepare_ccache_env(ccache_path: str | None) -> None:
    if not ccache_path:
        raise ValueError("ccache_path is required for Kerberos authentication")
    if not os.path.isfile(ccache_path):
        raise FileNotFoundError(ccache_path)
    os.environ["KRB5CCNAME"] = ccache_path
