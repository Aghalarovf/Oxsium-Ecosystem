from __future__ import annotations

import json
from pathlib import Path

_CONSTANTS_PATH = Path(__file__).resolve().parent / "constants.json"

with open(_CONSTANTS_PATH, "r", encoding="utf-8") as _f:
    _DATA = json.load(_f)

UAC_FLAGS: dict[str, int] = _DATA["uac_flags"]
RIGHT_MASKS: dict[str, int] = _DATA["right_masks"]
WELL_KNOWN_SIDS: dict[str, str] = _DATA["well_known_sids"]
ENCRYPTION_TYPES: dict[str, int] = _DATA["encryption_types"]
GROUP_TYPE_FLAGS: dict[str, int] = _DATA["group_type_flags"]