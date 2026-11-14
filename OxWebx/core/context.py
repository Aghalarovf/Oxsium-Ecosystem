from __future__ import annotations

import threading
from typing import Any, Optional

from core import events as ev
from core.config import Settings
from core.dns_client import DnsClient
from core.events import EventBus
from core.http_client import HttpClient, RateLimiter
from core.logger import Logger
from core.models import Target
from core.scope import Scope


class ScanContext:
    def __init__(
        self,
        target: Target,
        settings: Settings,
        scope: Scope,
        logger: Logger,
        events: EventBus,
        http: HttpClient,
        dns: DnsClient,
        limiter: RateLimiter,
        profile: str,
    ) -> None:
        self.target = target
        self.settings = settings
        self.scope = scope
        self.logger = logger
        self.events = events
        self.http = http
        self.dns = dns
        self.limiter = limiter
        self.profile = profile
        self._shared: dict[str, Any] = {}
        self._lock = threading.RLock()

    @property
    def passive_only(self) -> bool:
        return bool(self.settings.get("scan.passive_only", False))

    @property
    def active_allowed(self) -> bool:
        return self.scope.allow_active and not self.passive_only

    def option(self, module: str, key: str, default: Any = None) -> Any:
        return self.settings.get(f"modules.{module}.{key}", default)

    def may_contact(self, host: str) -> bool:
        return self.active_allowed and self.scope.host_in_scope(host)

    def share(self, key: str, value: Any) -> None:
        with self._lock:
            self._shared[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._shared.get(key, default)

    def extend_shared(self, key: str, values: list[Any]) -> list[Any]:
        with self._lock:
            current = self._shared.setdefault(key, [])
            for value in values:
                if value not in current:
                    current.append(value)
            return list(current)

    def emit(self, event: str, **payload: Any) -> None:
        self.events.emit(event, **payload)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._shared)


def create_context(
    target: Target,
    settings: Settings,
    scope: Scope,
    logger: Logger,
    events: EventBus,
    profile: str,
) -> ScanContext:
    rate = settings.section("network.rate_limit")
    limiter = RateLimiter(rate.get("delay", 0.0), rate.get("jitter", 0.0))
    http = HttpClient(settings, logger, limiter)
    dns = DnsClient(settings, logger, limiter)
    return ScanContext(
        target=target,
        settings=settings,
        scope=scope.for_target(target.host),
        logger=logger,
        events=events,
        http=http,
        dns=dns,
        limiter=limiter,
        profile=profile,
    )
