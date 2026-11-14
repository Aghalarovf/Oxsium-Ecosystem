from __future__ import annotations

from abc import ABC, abstractmethod

from core.session import Session


class ModuleResult(list):
    """List of collected records plus the collector result.

    `result` is the dict the JSONL backend needs (success/count/meta/error).
    It is never None, so a failed collector still produces a header line
    for its snapshot instead of silently writing nothing.
    """

    def __init__(self, records=(), result: dict | None = None):
        super().__init__(records)
        self.result = result if result is not None else {
            "success": True,
            "count": len(records) if hasattr(records, "__len__") else 0,
            "error": None,
            "meta": {},
        }


class BaseModule(ABC):
    name: str = ""

    @abstractmethod
    def run(self, session: Session) -> list:
        raise NotImplementedError
