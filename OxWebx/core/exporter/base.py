from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from core.models import ScanReport


class Exporter(ABC):
    name = ""

    @abstractmethod
    def export(self, report: ScanReport, path: Path | None = None) -> Any:
        raise NotImplementedError
