from __future__ import annotations

import argparse
import sys

from core.config import Config
from core.logger import setup_logger
from engine.pipeline import PROCESSORS, run


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m engine")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("-m", "--modules", nargs="+", choices=list(PROCESSORS), default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logger = setup_logger(args.verbose)
    run(args.output_dir or Config.OUTPUT_DIR, args.modules, logger)
    return 0


if __name__ == "__main__":
    sys.exit(main())
