from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable

SCAN_STARTED = "scan_started"
SCAN_FINISHED = "scan_finished"
MODULE_STARTED = "module_started"
MODULE_FINISHED = "module_finished"
MODULE_FAILED = "module_failed"
MODULE_SKIPPED = "module_skipped"
CHECK_STARTED = "check_started"
CHECK_FINISHED = "check_finished"
CHECK_FAILED = "check_failed"
FINDING = "finding"

Handler = Callable[..., None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._lock = threading.Lock()
        self.errors: list[str] = []

    def subscribe(self, event: str, handler: Handler) -> None:
        with self._lock:
            self._handlers[event].append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        self.subscribe("*", handler)

    def emit(self, event: str, **payload: Any) -> None:
        with self._lock:
            handlers = list(self._handlers.get(event, ())) + list(self._handlers.get("*", ()))
        for handler in handlers:
            try:
                handler(event, **payload)
            except Exception as exc:
                self.errors.append(f"event handler failed for {event}: {exc}")
