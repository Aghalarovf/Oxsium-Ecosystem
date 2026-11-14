from __future__ import annotations

import sys
from pathlib import Path

sys.pycache_prefix = str(Path(__file__).resolve().parent / "pycache")

from api.backends import JSONLBackend
from core import cli, modules
from core.config import Config
from core.logger import setup_logger
from core.session import Credentials, Session
from engine import pipeline


def main() -> int:
    args = cli.parse()
    logger = setup_logger(args.verbose)

    output_dir = args.output_dir or Config.OUTPUT_DIR

    credentials = Credentials(
        domain=args.domain,
        username=args.username,
        password=args.password,
        nt_hash=args.nt_hash,
        ccache_path=args.ccache,
    )

    session = Session(
        target=args.ip,
        credentials=credentials,
        dc_host=args.dc_host,
        use_ssl=args.use_ssl,
        enumerate_ip=args.enumerate_ip,
    )

    if args.enumerate_ip and "computers" not in modules.resolve_order(args.modules):
        logger.warning("--enumerate-ip has no effect without the computers module")

    try:
        results = modules.run(session, args.modules, logger)
    except Exception as exc:
        logger.error(f"scan failed: {exc}")
        return 1
    finally:
        session.close()

    backend = JSONLBackend(output_dir)
    for name, path in backend.write_all(results).items():
        logger.info(f"[{name}] written to {path}")

    # raw_*.jsonl + domain_aces.jsonl -> domain_*.jsonl
    engine_modules = [name for name in results if name in pipeline.PROCESSORS]
    if engine_modules:
        pipeline.run(output_dir, engine_modules, logger)

    return 0


if __name__ == "__main__":
    sys.exit(main())