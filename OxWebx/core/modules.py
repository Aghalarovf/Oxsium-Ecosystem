from __future__ import annotations

import importlib
import pkgutil
import traceback
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Callable, Optional

from core import events as ev
from core.exceptions import ModuleError
from core.models import Finding, ModuleResult, Severity
from core.utils import ROOT

if TYPE_CHECKING:
    from core.context import ScanContext


class Check(ABC):
    module = ""
    name = ""
    description = ""
    passive = True
    domain_only = False

    def __init__(self, ctx: "ScanContext") -> None:
        self.ctx = ctx
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.tag_resolver: Optional[Callable[[str], list[str]]] = None

    def option(self, key: str, default: Any = None) -> Any:
        return self.ctx.settings.get(f"modules.{self.module}.{self.name}.{key}", default)

    def add(
        self,
        finding_id: str,
        title: str,
        severity: Severity | str,
        description: str = "",
        evidence: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
        confidence: Optional[str] = None,
    ) -> Finding:
        finding = Finding(
            id=finding_id,
            title=title,
            severity=Severity.parse(severity),
            module=self.module,
            check=self.name,
            description=description,
            evidence=evidence or {},
            target=self.ctx.target.host,
            tags=list(tags) if tags else (self.tag_resolver(finding_id) if self.tag_resolver else []),
            confidence=confidence,
        )
        self.findings.append(finding)
        self.ctx.emit(ev.FINDING, finding=finding)
        return finding

    def fail(self, message: str) -> None:
        self.errors.append(message)
        self.ctx.logger.debug(f"{self.module}.{self.name}: {message}")

    @abstractmethod
    def run(self) -> dict[str, Any]:
        raise NotImplementedError


class BaseModule(ABC):
    name = ""
    description = ""
    category = "general"
    passive = False
    requires: tuple[str, ...] = ()
    version = "1.0.0"

    def __init__(self, ctx: "ScanContext") -> None:
        self.ctx = ctx

    def applicable(self) -> tuple[bool, str]:
        return True, ""

    @abstractmethod
    def run(self) -> ModuleResult:
        raise NotImplementedError

    @classmethod
    def info(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "category": cls.category,
            "passive": cls.passive,
            "requires": list(cls.requires),
            "version": cls.version,
        }


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, type[BaseModule]] = {}
        self.stubs: list[str] = []
        self.failed: dict[str, str] = {}
        self.sources: dict[str, str] = {}

    def register(self, cls: type[BaseModule], source: str = "builtin") -> None:
        if not cls.name:
            raise ModuleError(f"module class {cls.__name__} has no name")
        if cls.name in self._modules and self.sources.get(cls.name) == "builtin" and source != "builtin":
            raise ModuleError(f"extension cannot override built-in module '{cls.name}'")
        self._modules[cls.name] = cls
        self.sources[cls.name] = source

    def get(self, name: str) -> type[BaseModule]:
        if name not in self._modules:
            raise ModuleError(f"unknown module '{name}', available: {', '.join(self.names()) or 'none'}")
        return self._modules[name]

    def names(self) -> list[str]:
        return sorted(self._modules)

    def has(self, name: str) -> bool:
        return name in self._modules

    def all(self) -> list[type[BaseModule]]:
        return [self._modules[n] for n in self.names()]

    def discover(self, package: str = "modules") -> None:
        base = ROOT / package
        if not base.is_dir():
            return
        for info in sorted(pkgutil.iter_modules([str(base)]), key=lambda i: i.name):
            if not info.ispkg:
                continue
            if not (base / info.name / "module.py").is_file():
                self.stubs.append(info.name)
                continue
            try:
                loaded = importlib.import_module(f"{package}.{info.name}.module")
            except Exception as exc:
                self.failed[info.name] = f"{type(exc).__name__}: {exc}"
                continue
            cls = getattr(loaded, "MODULE", None)
            if cls is None or not issubclass(cls, BaseModule):
                self.failed[info.name] = "module.py does not expose MODULE"
                continue
            self.register(cls)

    def load_extensions(self, names: list[str], exporters: Any, logger: Any = None) -> list[str]:
        loaded: list[str] = []
        for name in names:
            path = ROOT / "extensions" / name / "plugin.py"
            if not path.is_file():
                self.failed[f"extension:{name}"] = "plugin.py not found"
                continue
            try:
                plugin = importlib.import_module(f"extensions.{name}.plugin")
                register = getattr(plugin, "register")
                register(self, exporters)
                loaded.append(name)
            except Exception as exc:
                self.failed[f"extension:{name}"] = f"{type(exc).__name__}: {exc}"
                if logger is not None:
                    logger.debug(traceback.format_exc())
        return loaded


def resolve_order(registry: ModuleRegistry, names: list[str]) -> list[list[str]]:
    selected = list(dict.fromkeys(names))
    pending = {}
    for name in selected:
        cls = registry.get(name)
        deps = [d for d in cls.requires if d in selected]
        missing = [d for d in cls.requires if d not in selected and not registry.has(d)]
        if missing:
            raise ModuleError(f"module '{name}' requires unknown module(s): {', '.join(missing)}")
        pending[name] = set(deps)
    levels: list[list[str]] = []
    done: set[str] = set()
    while pending:
        ready = sorted(n for n, deps in pending.items() if deps <= done)
        if not ready:
            raise ModuleError(f"dependency cycle among modules: {', '.join(sorted(pending))}")
        levels.append(ready)
        done.update(ready)
        for n in ready:
            pending.pop(n)
    return levels