from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_ACL_PATH = Path(__file__).resolve().parent / "acl.json"
_EXTENDED_RIGHTS_PATH = Path(__file__).resolve().parent / "extended_rights.json"


@lru_cache(maxsize=1)
def load_acl_risk() -> dict[str, str]:
    with open(_ACL_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_extended_rights_risk() -> dict[str, str]:
    with open(_EXTENDED_RIGHTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
