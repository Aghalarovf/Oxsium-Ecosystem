from __future__ import annotations

from pathlib import Path
from typing import Any

from core.exporter.base import Exporter
from core.logger import Logger
from core.models import ScanReport


class ConsoleExporter(Exporter):
    name = "console"

    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def export(self, report: ScanReport, path: Path | None = None) -> Any:
        summary = report.summary()
        self.logger.ok(f"{report.target.host}: {summary['findings_total']} findings")
        for finding in report.findings():
            self.logger.info(f"[{finding.severity.value}] {finding.title}")
        return summary
