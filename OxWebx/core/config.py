from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Optional

from core.exceptions import ConfigError
from core.utils import ROOT, deep_merge

try:
    import yaml
except ImportError:
    yaml = None

CONFIG_DIR = ROOT / "config"
PROFILES_DIR = CONFIG_DIR / "profiles"
DEFAULT_FILE = CONFIG_DIR / "default.yaml"
SCOPE_FILE = CONFIG_DIR / "scope.yaml"

_MISSING = object()


class Settings:
    def __init__(self, data: Optional[dict] = None) -> None:
        self._data: dict[str, Any] = data if data is not None else {}

    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return default if node is None and default is not None else node

    def section(self, path: str) -> "Settings":
        value = self.get(path, {})
        return Settings(value if isinstance(value, dict) else {})

    def set(self, path: str, value: Any) -> None:
        parts = path.split(".")
        node = self._data
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = value

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)

    def clone(self) -> "Settings":
        return Settings(copy.deepcopy(self._data))

    def __contains__(self, path: str) -> bool:
        return self.get(path, _MISSING) is not _MISSING


def read_yaml(path: Path) -> dict:
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        data = yaml.safe_load(text) if yaml is not None else _parse_simple_yaml(text)
    except Exception as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    data = data or {}
    if not isinstance(data, dict):
        raise ConfigError(f"top-level YAML object expected in {path}")
    return data


def list_profiles() -> list[str]:
    if not PROFILES_DIR.is_dir():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))


def parse_override(expression: str) -> tuple[str, Any]:
    if "=" not in expression:
        raise ConfigError(f"override must look like key=value: {expression}")
    key, raw = expression.split("=", 1)
    key = key.strip()
    if not key:
        raise ConfigError(f"empty key in override: {expression}")
    value = yaml.safe_load(raw) if yaml is not None else _parse_scalar(raw)
    return key, value


def _parse_scalar(value: str) -> Any:
    import ast

    text = value.strip()
    lowered = text.lower()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [] if not inner else [_parse_scalar(item) for item in inner.split(",")]
    if lowered in {"null", "~"}:
        return None
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text.strip("\"'")


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()
        if line.startswith("- "):
            while stack[-1][0] >= indent:
                stack.pop()
            container = stack[-1][1]
            if isinstance(container, list):
                container.append(_parse_scalar(line[2:]))
                continue
            if not isinstance(container, dict):
                raise ValueError(f"invalid list line: {line}")
            current = stack[-1][1]
            parent = stack[-2][1] if len(stack) > 1 else None
            if not isinstance(parent, dict):
                raise ValueError(f"invalid list parent: {line}")
            key = next((name for name, value in parent.items() if value is current), None)
            if key is None:
                raise ValueError(f"invalid list parent: {line}")
            values = parent[key] = []
            stack[-1] = (stack[-1][0], values)
            values.append(_parse_scalar(line[2:]))
            continue
        if ":" not in line:
            raise ValueError(f"invalid mapping line: {line}")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if not isinstance(parent, dict):
            raise ValueError(f"mapping follows list: {line}")
        if raw_value.strip():
            value = raw_value.strip()
            if value.startswith("[") and value.endswith("]"):
                inner = value[1:-1].strip()
                parsed = [] if not inner else [_parse_scalar(item) for item in inner.split(",")]
                parent[key] = parsed
            else:
                parent[key] = _parse_scalar(value)
        else:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
    return root


def load_settings(
    profile: Optional[str] = None,
    config_file: Optional[str] = None,
    scope_file: Optional[str] = None,
    overrides: Optional[list[str]] = None,
) -> tuple[Settings, str]:
    data = read_yaml(DEFAULT_FILE)
    selected = profile or data.get("scan", {}).get("profile") or "quick"

    available = list_profiles()
    if selected not in available:
        raise ConfigError(f"unknown profile '{selected}', available: {', '.join(available) or 'none'}")
    data = deep_merge(data, read_yaml(PROFILES_DIR / f"{selected}.yaml"))

    if config_file:
        data = deep_merge(data, read_yaml(Path(config_file)))

    scope_path = Path(scope_file) if scope_file else SCOPE_FILE
    data["scope"] = deep_merge(data.get("scope", {}), read_yaml(scope_path))

    settings = Settings(data)
    for expression in overrides or []:
        key, value = parse_override(expression)
        settings.set(key, value)
    settings.set("scan.profile", selected)
    settings.set("scan.config_file", str(config_file) if config_file else None)
    settings.set("scan.overrides", list(overrides or []))
    return settings, selected