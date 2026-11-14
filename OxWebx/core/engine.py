from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Optional

from core.context import create_context
from core.events import MODULE_FAILED, MODULE_SKIPPED, SCAN_FINISHED, SCAN_STARTED, EventBus
from core.exceptions import ModuleError
from core.models import ModuleResult, ScanReport, Target
from core.modules import ModuleRegistry, resolve_order
from core.scope import Scope
from core.config import Settings
from core.logger import Logger

MODULE_ALIASES = {
    "whois": "whois_dns",
    "archive": "archive_dorks",
    "js": "javascript_analyzer",
    "risk": "risk_assessment",
    "map": "sitemap_graph",
    "subdomain": "subdomain_discovery",
    "traffic": "traffic_analyzer",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScanEngine:
    def __init__(
        self,
        settings: Settings,
        logger: Logger,
        registry: Optional[ModuleRegistry] = None,
        events: Optional[EventBus] = None,
    ) -> None:
        self.settings = settings
        self.logger = logger
        self.registry = registry or ModuleRegistry()
        self.events = events or EventBus()
        if not self.registry.names():
            self.registry.discover()

    def select_modules(self) -> list[str]:
        configured = self.settings.get("scan.modules", "all")
        if configured == "all":
            names = self.registry.names()
        elif isinstance(configured, (list, tuple, set)):
            names = [str(name) for name in configured]
        else:
            names = [str(configured)]
        if "all" in names:
            if len(names) != 1:
                raise ModuleError("'all' cannot be combined with other modules")
            names = self.registry.names()
        names = [MODULE_ALIASES.get(name, name) for name in names]
        excluded = {str(name) for name in self.settings.get("scan.exclude_modules", [])}
        selected = [name for name in names if name not in excluded]
        if not selected:
            raise ModuleError("no modules selected")
        return selected

    def run(self, raw_target: str) -> ScanReport:
        target = Target.parse(raw_target)
        scope = Scope(self.settings.get("scope", {}))
        scope.validate_target(target.host)
        profile = str(self.settings.get("scan.profile", "quick"))
        context = create_context(target, self.settings, scope, self.logger, self.events, profile)
        report = ScanReport(
            tool="OxWebx",
            version="1.0.0",
            target=target,
            profile=profile,
            started_at=_timestamp(),
            scope=context.scope.describe(),
            config={
                "config_file": self.settings.get("scan.config_file"),
                "overrides": list(self.settings.get("scan.overrides", []) or []),
                "customized": bool(self.settings.get("scan.config_file") or self.settings.get("scan.overrides")),
            },
        )
        selected = self.select_modules()
        levels = resolve_order(self.registry, selected)
        self.events.emit(SCAN_STARTED, target=target.host, modules=selected)
        started = monotonic()
        for level in levels:
            workers = max(1, int(self.settings.get("scan.module_workers", 1)))
            if workers == 1 or len(level) == 1:
                results = [self._run_module(name, context) for name in level]
            else:
                with ThreadPoolExecutor(max_workers=min(workers, len(level))) as pool:
                    results = list(pool.map(lambda name: self._run_module(name, context), level))
            for name, result in zip(level, results):
                report.modules[name] = result
        report.finished_at = _timestamp()
        report.duration = monotonic() - started
        report.errors.extend(self.events.errors)
        self.events.emit(SCAN_FINISHED, report=report)
        return report

    def _run_module(self, name: str, context: Any) -> ModuleResult:
        module_cls = self.registry.get(name)
        module = module_cls(context)
        applicable, reason = module.applicable()
        if not applicable:
            self.events.emit(MODULE_SKIPPED, module=name, reason=reason)
            return ModuleResult(module=name, status="skipped", skipped_reason=reason)
        try:
            return module.run()
        except Exception as exc:
            message = f"{name}: {type(exc).__name__}: {exc}"
            self.events.emit(MODULE_FAILED, module=name, error=message)
            self.logger.debug(message)
            return ModuleResult(module=name, status="failed", errors=[message])