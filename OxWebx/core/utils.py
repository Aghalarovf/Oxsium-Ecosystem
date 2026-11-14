from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

from core.exceptions import ConfigError

ROOT = Path(__file__).resolve().parent.parent
SIGNATURES_DIR = ROOT / "signatures"

SECOND_LEVEL_LABELS = frozenset({
    "co", "com", "net", "org", "gov", "edu", "ac", "mil", "ne", "or", "gr",
    "sch", "nhs", "police", "mod", "info", "biz", "name", "pp", "int", "go",
})

PARSE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d-%b-%Y %H:%M:%S",
    "%Y.%m.%d %H:%M:%S",
    "%Y.%m.%d",
    "%d.%m.%Y",
    "%m/%d/%Y",
)

HOSTNAME_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


@lru_cache(maxsize=None)
def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_signature(*parts: str) -> Any:
    path = SIGNATURES_DIR.joinpath(*parts)
    if not path.is_file():
        raise ConfigError(f"signature file not found: {path}")
    return _read_json(str(path))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def normalize_host(value: str) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            return text[1:end]
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if is_ip(text):
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return text


def valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    return all(HOSTNAME_LABEL.match(label) for label in labels)


def _uses_second_level(labels: list[str]) -> bool:
    return len(labels) >= 3 and labels[-2] in SECOND_LEVEL_LABELS and len(labels[-1]) == 2


def registered_domain(host: str) -> str:
    labels = host.rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if _uses_second_level(labels):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def tld_of(host: str) -> str:
    labels = host.rstrip(".").split(".")
    if _uses_second_level(labels):
        return ".".join(labels[-2:])
    return labels[-1]


def first(*values: Any) -> Optional[Any]:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, tuple, dict, set)) and not value:
            continue
        return value
    return None


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            text = str(item).strip()
            if text and text not in out:
                out.append(text)
        return out
    text = str(value).strip()
    return [text] if text else []


def dedupe(items: Iterable[Any]) -> list[Any]:
    seen: set = set()
    out: list[Any] = []
    for item in items:
        key = item if isinstance(item, (str, int, tuple)) else repr(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def truncate(text: str, limit: int = 200) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def deep_merge(base: dict, patch: dict) -> dict:
    result = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    text = re.sub(r"\s*\(.*\)$", "", text)
    parsed: Optional[datetime] = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" UTC", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in PARSE_FORMATS:
            for candidate in (text, text[:19], text[:10]):
                try:
                    parsed = datetime.strptime(candidate, fmt)
                    break
                except ValueError:
                    continue
            if parsed is not None:
                break
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_dt(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        return str(value).strip()
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def days_until(value: Optional[str]) -> Optional[int]:
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    return (parsed - now_utc()).days


def days_since(value: Optional[str]) -> Optional[int]:
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    return (now_utc() - parsed).days


def parse_asn(text: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    if not text:
        return None, None
    text = str(text).strip()
    match = re.search(r"AS(\d+)\s*(.*)$", text, re.I)
    if match:
        return int(match.group(1)), (match.group(2).strip() or None)
    if text.isdigit():
        return int(text), None
    return None, text


def flatten_vcard(vcard: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return out
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = str(item[0]).lower()
        value = item[3]
        if key == "fn" and isinstance(value, str):
            out["name"] = value
        elif key == "org":
            if isinstance(value, list) and value:
                out["organization"] = str(value[0])
            elif isinstance(value, str):
                out["organization"] = value
        elif key == "email" and isinstance(value, str):
            out["email"] = value
        elif key == "tel":
            out["phone"] = str(value)
        elif key == "adr":
            if isinstance(value, list):
                parts = [str(x) for x in value if x]
            else:
                parts = [str(value)] if value else []
            label = item[1].get("label") if isinstance(item[1], dict) else None
            if label:
                parts = [str(label).replace("\n", ", ")]
            if parts:
                out["address"] = ", ".join(parts)
    return out


def looks_privacy(text: str) -> bool:
    blob = text.lower()
    hints = load_signature("dns", "privacy_hints.json")["hints"]
    return any(hint in blob for hint in hints)


def reverse_labels(ip: str) -> Optional[str]:
    try:
        pointer = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None
    for suffix in (".in-addr.arpa", ".ip6.arpa"):
        if pointer.endswith(suffix):
            return pointer[: -len(suffix)]
    return pointer


def reverse_pointer(ip: str) -> Optional[str]:
    try:
        return ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"
