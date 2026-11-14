from __future__ import annotations

import struct

from utils.constants import WELL_KNOWN_SIDS


def sid_bytes_to_str(data: bytes) -> str:
    revision = data[0]
    sub_authority_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    sid = f"S-{revision}-{identifier_authority}"
    for i in range(sub_authority_count):
        offset = 8 + 4 * i
        sub_authority = struct.unpack("<I", data[offset:offset + 4])[0]
        sid += f"-{sub_authority}"
    return sid


def resolve_well_known_sid(sid: str) -> str | None:
    return WELL_KNOWN_SIDS.get(sid)


def rid_from_sid(sid: str) -> int | None:
    parts = sid.split("-")
    if len(parts) < 2:
        return None
    try:
        return int(parts[-1])
    except ValueError:
        return None
