import os
import sys
from pathlib import Path

_cache_root = Path(__file__).resolve().parent / "pycache"
_cache_root.mkdir(exist_ok=True)
os.environ.setdefault("PYTHONPYCACHEPREFIX", str(_cache_root))
sys.pycache_prefix = str(_cache_root)

from pycache import configure

configure()

from core.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
