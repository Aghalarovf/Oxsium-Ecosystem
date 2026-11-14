import ipaddress
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, _PROJECT_ROOT)
sys.pycache_prefix = os.path.join(_PROJECT_ROOT, "pycache")

from core import cli, engine, exporter
from core.dns_resolver import get_scan_source, load_subnets_from_file, load_targets_from_file
from core.logger import setup_logger
from plugins.registry import get_module


def _pick_route_sample(config, subnets) -> str:
    if subnets:
        return subnets[0].split("/")[0]
    if config.targets_raw:
        return config.targets_raw[0]
    if config.cidr:
        return config.cidr.split("/")[0]
    if config.ip_range:
        return config.ip_range.split("-")[0].strip()
    if config.input_file:
        try:
            with open(config.input_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        return line
        except OSError:
            pass
    return "8.8.8.8"


def _subnets_meta_from_direct_scan_file(path: str) -> list:
    subnets: list = []
    seen = set()
    for line in load_targets_from_file(path):
        if "/" in line:
            key = str(ipaddress.ip_network(line, strict=False))
        else:
            key = str(ipaddress.ip_network(f"{line}/24", strict=False))
        if key not in seen:
            seen.add(key)
            subnets.append(key)
    return subnets


def _subnets_meta_from_results(results) -> list:
    subnets: list = []
    seen = set()
    for result in results:
        key = str(ipaddress.ip_network(f"{result.host.ip}/24", strict=False))
        if key not in seen:
            seen.add(key)
            subnets.append(key)
    subnets.sort(key=lambda s: ipaddress.ip_network(s).network_address)
    return subnets


def _build_template_meta(config, mode: str, results=None) -> dict:
    if config.subnets_file:
        if config.output_dir:
            subnets = _subnets_meta_from_results(results or [])
        elif config.skip_discovery:
            subnets = _subnets_meta_from_direct_scan_file(config.subnets_file)
        else:
            subnets = load_subnets_from_file(config.subnets_file)
    elif config.cidr:
        subnets = [config.cidr]
    else:
        subnets = []

    route_sample = _pick_route_sample(config, subnets)
    host_ip = get_scan_source(route_sample)

    return {
        "mode": mode,
        "threads": config.threads,
        "port_scan": mode == "port_scan",
        "host_scan": mode == "host_scan",
        "host_ip": host_ip,
        "subnets": subnets,
    }


def _requested_outputs(config) -> dict:
    return {
        "normal": config.output_normal,
        "json": config.output_json,
        "csv": config.output_csv,
    }


def _any_output_requested(config) -> bool:
    return any(_requested_outputs(config).values())


_MODULE_PRINTERS = {
    "anonymous": exporter.print_anonymous_results,
    "http_enum": exporter.print_http_enum_results,
    "modbus": exporter.print_modbus_results,
}


def _run_modules(config, results, logger):
    for module_name in config.modules:
        module = get_module(module_name)
        if module is None:
            logger.warning(f"Unknown module: {module_name}")
            continue
        module_results = module.run(results, config.module_options, logger=logger)
        printer = _MODULE_PRINTERS.get(module_name, exporter.print_anonymous_results)
        printer(module_results)


try:
    from core.version_checker import check_and_update as _check_version
except Exception:
    _check_version = None


def main():
    if _check_version is not None:
        _check_version(background=True)

    config = cli.parse_args()
    logger = setup_logger(config.verbose)

    if config.host_list_input and config.host_list_all_subnets:
        zip_path = os.path.splitext(config.host_list_input)[0] + "_subnets.zip"
        subnet_count = exporter.export_host_lists_by_subnet_zip(config.host_list_input, zip_path)
        logger.info(f"{subnet_count} subnet file(s) written to {zip_path}")
        sys.exit(0)

    if config.host_list_input:
        written = exporter.export_host_list_from_json(config.host_list_input, config.host_list_subnet, config.host_list_output)
        logger.info(f"{written} host(s) from {config.host_list_subnet} written to {config.host_list_output}")
        sys.exit(0)

    try:
        results = engine.run(config)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        sys.exit(1)

    if not results:
        sys.exit(0)

    if config.subnets_file:
        subnets_mode = "port_scan" if (config.skip_discovery or config.output_dir) else "host_scan"
        if _any_output_requested(config):
            exporter.export_multi(
                results, _requested_outputs(config),
                template_meta=_build_template_meta(config, subnets_mode, results),
            )
        _run_modules(config, results, logger)
        sys.exit(0)

    discovery_only = bool(config.ping_only or config.only_host or config.cidr)
    mode = "host_scan" if discovery_only else "port_scan"

    already_printed_live = config.live and not _any_output_requested(config)
    if not already_printed_live:
        exporter.export_multi(
            results, _requested_outputs(config),
            template_meta=_build_template_meta(config, mode),
        )

    _run_modules(config, results, logger)


if __name__ == "__main__":
    main()