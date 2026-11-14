from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.config import list_profiles, load_settings
from core.engine import MODULE_ALIASES, ScanEngine
from core.exceptions import OxwebxError
from core.exporter import ExporterManager
from core.logger import Logger
from modules.whois_dns.module import CHECKS
from core.utils import safe_filename


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oxwebx")
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("target", nargs="?")
    targets.add_argument("-i", "--input", dest="input_file", help="file containing one domain or IP address per line")
    parser.add_argument(
        "-m",
        "--module",
        dest="modules",
        nargs="+",
        choices=[*MODULE_ALIASES, "all"],
        help="modules to run: whois, archive, js, risk, map, subdomain, traffic or all",
    )
    parser.add_argument(
        "--phase",
        choices=sorted(CHECKS),
        help="run only one whois phase when used with -m whois",
    )
    parser.add_argument("-p", "--profile", choices=list_profiles())
    parser.add_argument("-c", "--config")
    parser.add_argument("--scope")
    parser.add_argument("--set", dest="overrides", action="append", default=[])
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        targets = _load_targets(args.target, args.input_file)
        overrides = list(args.overrides)
        if args.modules and "whois" in args.modules and not any(item.startswith("modules.whois_dns.checks=") for item in overrides):
            overrides.append(f"modules.whois_dns.checks=[{', '.join(CHECKS)}]")
        settings, _ = load_settings(args.profile, args.config, args.scope, overrides)
        if args.modules:
            settings.set("scan.modules", args.modules)
        if args.phase:
            if args.modules != ["whois"]:
                raise OxwebxError("--phase requires exactly '-m whois'")
            settings.set("modules.whois_dns.checks", [args.phase])
        logging_settings = settings.section("logging")
        logger = Logger(
            level=str(logging_settings.get("level", "info")),
            color=bool(settings.get("output.color", True)),
            quiet=args.quiet,
            progress_events=bool(logging_settings.get("progress_events", False)),
        )
        engine = ScanEngine(settings, logger)
        formats = [str(value) for value in settings.get("output.formats", ["console", "json"])]
        exporters = ExporterManager(logger)
        failed = False
        selected = engine.select_modules()
        whois_output = "whois_dns" in selected
        for target in targets:
            try:
                report = engine.run(target)
                filename = f"{safe_filename(report.target.host)}_whois_dns.json" if whois_output else None
                exporters.export(
                    report,
                    formats,
                    str(settings.get("output.directory", "results")),
                    filename=filename,
                )
                failed = failed or bool(report.errors)
            except OxwebxError as exc:
                logger.error(f"{target}: {exc}")
                failed = True
        return 1 if failed else 0
    except OxwebxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _load_targets(target: str | None, input_file: str | None) -> list[str]:
    if target:
        return [target]
    if not input_file:
        raise OxwebxError("a target or --input file is required")
    path = Path(input_file)
    if not path.is_file():
        raise OxwebxError(f"input file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OxwebxError(f"unable to read input file: {exc}") from exc
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise OxwebxError(f"invalid JSON input file: {exc}") from exc
        if not isinstance(data, list):
            raise OxwebxError("JSON input must contain an array of targets")
        targets = [str(value).strip() for value in data if str(value).strip()]
    else:
        targets = [
            line.split("#", 1)[0].strip()
            for line in text.splitlines()
            if line.split("#", 1)[0].strip()
        ]
    if not targets:
        raise OxwebxError("input file contains no targets")
    return list(dict.fromkeys(targets))


if __name__ == "__main__":
    raise SystemExit(main())