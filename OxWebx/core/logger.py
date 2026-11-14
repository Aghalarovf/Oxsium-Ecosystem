from __future__ import annotations

import json
import sys
import threading
from typing import Any, Optional, TextIO

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}

CODES = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}
RESET = "\033[0m"


class Logger:
    def __init__(
        self,
        level: str = "info",
        color: bool = True,
        quiet: bool = False,
        progress_events: bool = False,
        stream: Optional[TextIO] = None,
        err_stream: Optional[TextIO] = None,
    ) -> None:
        self.level = LEVELS.get(level, 20)
        self.quiet = quiet
        self.progress_events = progress_events
        self.stream = stream or sys.stdout
        self.err_stream = err_stream or sys.stderr
        self.color = bool(color) and bool(getattr(self.stream, "isatty", lambda: False)())
        self._lock = threading.Lock()

    def paint(self, text: Any, *styles: str) -> str:
        text = str(text)
        if not self.color or not styles:
            return text
        prefix = "".join(CODES.get(s, "") for s in styles)
        return f"{prefix}{text}{RESET}"

    def _write(self, stream: TextIO, text: str) -> None:
        with self._lock:
            stream.write(text + "\n")
            stream.flush()

    def _emit(self, level: str, symbol: str, style: str, message: str, to_err: bool = False) -> None:
        if LEVELS[level] < self.level:
            return
        if self.quiet and level != "error":
            return
        line = f"  {self.paint(symbol, style)}  {message}"
        self._write(self.err_stream if (to_err or level == "error") else self.stream, line)

    def debug(self, message: str) -> None:
        self._emit("debug", "·", "dim", self.paint(message, "dim"), to_err=True)

    def info(self, message: str) -> None:
        self._emit("info", "→", "cyan", message)

    def ok(self, message: str) -> None:
        self._emit("info", "✔", "green", message)

    def warn(self, message: str) -> None:
        self._emit("warn", "⚠", "yellow", message)

    def error(self, message: str) -> None:
        self._emit("error", "✘", "red", message)

    def progress(self, event: str, **fields: Any) -> None:
        if not self.progress_events:
            return
        payload = {"event": event}
        payload.update(fields)
        self._write(self.err_stream, json.dumps(payload, default=str))
