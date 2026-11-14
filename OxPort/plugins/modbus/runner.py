from typing import List, Optional

from core.models import Protocol, ScanResult
from plugins.modbus import (
    modbus_diagnostics,
    modbus_discover,
    modbus_exception_status,
    modbus_fc_capability_map,
    modbus_fifo_probe,
    modbus_file_record_probe,
    modbus_latency_fingerprint,
    modbus_probe,
    modbus_tls_variant_check,
)
from plugins.modbus.base import ModbusDiscoverResult

MODULES = {
    "discover":             modbus_discover,
    "register_probe":       modbus_probe,
    "diagnostics":          modbus_diagnostics,
    "exception_status":     modbus_exception_status,
    "fc_capability_map":    modbus_fc_capability_map,
    "file_record_probe":    modbus_file_record_probe,
    "fifo_probe":           modbus_fifo_probe,
    "latency_fingerprint":  modbus_latency_fingerprint,
    "tls_variant_check":    modbus_tls_variant_check,
}

MODBUS_PORTS = {502, 503}
MODBUS_TLS_PORT = 802
_SERVICE_NAME_TO_MODBUS = {"MODBUS", "MODBUS-ALT"}


def _is_modbus_port(port_result) -> bool:
    service_name = (port_result.service_name or "").upper()
    if service_name in _SERVICE_NAME_TO_MODBUS:
        return True
    return port_result.port in MODBUS_PORTS | {MODBUS_TLS_PORT}


def plan_checks(scan_results: List[ScanResult]):
    planned = []
    for scan_result in scan_results:
        if not scan_result.host.alive:
            continue
        for port_result in scan_result.open_ports():
            if port_result.protocol != Protocol.TCP:
                continue
            if not _is_modbus_port(port_result):
                continue
            planned.append((scan_result.host.ip, port_result))
    return planned


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _int_opt(options: dict, *keys, default: int) -> int:
    for k in keys:
        v = options.get(k)
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
    return default


def _attach_per_unit(module_key: str, module, discover_results: List[ModbusDiscoverResult],
                     host_ip: str, port: int, protocol_value: str,
                     timeout_ms: int, options: dict, logger) -> List[ModbusDiscoverResult]:
    unit_ids = [r.unit_id for r in discover_results if r.responsive and r.unit_id >= 0]
    if not unit_ids:
        unit_ids = [1]

    extra: List[ModbusDiscoverResult] = []

    for uid in unit_ids:
        if logger:
            logger.info(f"modbus[{module_key}]: {host_ip}:{port} unit_id={uid}")
        try:
            if module_key == "register_probe":
                start = _int_opt(options, "PROBE_START", "probe_start", default=0)
                count = _int_opt(options, "PROBE_COUNT", "probe_count", default=8)
                results = module.run(host_ip, port, unit_id=uid, timeout_ms=timeout_ms,
                                     start_address=start, count=count, logger=logger)
            elif module_key == "latency_fingerprint":
                samples = _int_opt(options, "LATENCY_SAMPLES", "latency_samples", default=5)
                results = module.run(host_ip, port, unit_id=uid, timeout_ms=timeout_ms,
                                     sample_count=samples, logger=logger)
            else:
                results = module.run(host_ip, port, unit_id=uid, timeout_ms=timeout_ms,
                                     logger=logger)
        except Exception as exc:
            if logger:
                logger.warning(f"modbus[{module_key}]: {host_ip}:{port} uid={uid} error: {exc}")
            continue

        if not results:
            continue

        result_obj = results[0]

        target_dr = next((dr for dr in discover_results if dr.unit_id == uid), None)
        if target_dr is None:
            stub = ModbusDiscoverResult(
                service="modbus", host=host_ip, port=port,
                protocol=protocol_value, unit_id=uid, responsive=True,
            )
            setattr(stub, module_key, result_obj)
            extra.append(stub)
        else:
            setattr(target_dr, module_key, result_obj)

    return extra


def run(scan_results: List[ScanResult], options: Optional[dict] = None,
        logger=None) -> List[ModbusDiscoverResult]:
    options = options or {}
    timeout_ms = _int_opt(options, "TIMEOUT", "timeout", default=2500)
    full_unit_scan = _truthy(options.get("FULL_UNIT_SCAN", options.get("full_unit_scan", "false")))

    requested = options.get("MODULES", options.get("modules"))
    if requested:
        if isinstance(requested, str):
            requested = [m.strip().lower() for m in requested.split(",") if m.strip()]
        enabled_modules = [m for m in requested if m in MODULES]
    else:
        enabled_modules = list(MODULES.keys())

    results: List[ModbusDiscoverResult] = []
    planned = plan_checks(scan_results)

    if not planned:
        if logger:
            logger.info("modbus module requested but no open Modbus port(s) found")
        return results

    if logger:
        logger.info(f"Running modbus enumeration on {len(planned)} open port(s): "
                    f"sub-modules={enabled_modules}")

    for host_ip, port_result in planned:
        port = port_result.port
        protocol_value = port_result.protocol.value
        discover_results: List[ModbusDiscoverResult] = []

        if "discover" in enabled_modules and port != MODBUS_TLS_PORT:
            if logger:
                logger.info(f"modbus[discover]: {host_ip}:{port}")
            try:
                discover_results = modbus_discover.discover(
                    host_ip, port, timeout_ms=timeout_ms,
                    full_unit_scan=full_unit_scan, logger=logger,
                )
            except Exception as exc:
                discover_results = [ModbusDiscoverResult(
                    service="modbus", host=host_ip, port=port,
                    protocol=protocol_value, unit_id=-1,
                    responsive=False, error=str(exc),
                )]

        if "tls_variant_check" in enabled_modules and port == MODBUS_TLS_PORT:
            if logger:
                logger.info(f"modbus[tls_variant_check]: {host_ip}:{port}")
            try:
                tls_results = modbus_tls_variant_check.run(
                    host_ip, port=port, timeout_ms=timeout_ms, logger=logger,
                )
                if tls_results and tls_results[0].any_finding:
                    tls_target = next(
                        (dr for dr in discover_results if dr.unit_id >= 0), None
                    )
                    if tls_target is None:
                        stub = ModbusDiscoverResult(
                            service="modbus", host=host_ip, port=port,
                            protocol=protocol_value, unit_id=1,
                            responsive=tls_results[0].modbus_over_tls_responsive or False,
                            tls_variant=tls_results[0],
                        )
                        discover_results.append(stub)
                    else:
                        tls_target.tls_variant = tls_results[0]
            except Exception as exc:
                if logger:
                    logger.warning(f"modbus[tls_variant_check]: {host_ip} error: {exc}")

        per_unit_modules = [
            m for m in enabled_modules
            if m not in ("discover", "tls_variant_check")
        ]
        for module_key in per_unit_modules:
            module = MODULES[module_key]
            extra = _attach_per_unit(
                module_key, module, discover_results,
                host_ip, port, protocol_value,
                timeout_ms, options, logger,
            )
            discover_results.extend(extra)

        results.extend(discover_results)

    return results
