from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.exporter.base import Exporter
from core.models import ScanReport


class JsonExporter(Exporter):
    name = "json"

    def export(self, report: ScanReport, path: Path | None = None) -> Any:
        payload = report.to_dict()
        if path is None:
            return payload
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=str), encoding="utf-8")
        return payload
