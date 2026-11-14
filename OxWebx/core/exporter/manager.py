from __future__ import annotations

from pathlib import Path
from typing import Any

from core.exporter.console import ConsoleExporter
from core.exporter.json_exporter import JsonExporter
from core.exceptions import ExporterError
from core.logger import Logger
from core.models import ScanReport


class ExporterManager:
    def __init__(self, logger: Logger) -> None:
        self.exporters = {
            "console": ConsoleExporter(logger),
            "json": JsonExporter(),
        }

    def export(
        self,
        report: ScanReport,
        formats: list[str],
        directory: str = "results",
        filename: str | None = None,
    ) -> dict[str, Any]:
        output: dict[str, Any] = {}
        root = Path(directory)
        for name in formats:
            exporter = self.exporters.get(name)
            if exporter is None:
                raise ExporterError(f"unknown exporter '{name}'")
            path = root / (filename or f"{report.target.host}.json") if name == "json" else None
            output[name] = exporter.export(report, path)
        return output
