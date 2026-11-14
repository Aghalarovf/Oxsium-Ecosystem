from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CACHE_ROOT = ROOT / "pycache"


def configure() -> Path:
    CACHE_ROOT.mkdir(exist_ok=True)
    prefix = str(CACHE_ROOT)
    os.environ.setdefault("PYTHONPYCACHEPREFIX", prefix)
    sys.pycache_prefix = prefix
    return CACHE_ROOT


def clean() -> None:
    for path in ROOT.rglob("__pycache__"):
        if path.is_dir():
            shutil.rmtree(path)
    if CACHE_ROOT.is_dir():
        shutil.rmtree(CACHE_ROOT)


if __name__ == "__main__":
    clean()
