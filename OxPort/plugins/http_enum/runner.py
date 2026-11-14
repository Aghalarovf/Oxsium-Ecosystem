from typing import List, Optional

from core.models import PortResult, Protocol, ScanResult
from plugins.http_enum.base import HttpEnumResult
from plugins.http_enum.prober import probe

HTTPS_PORTS = {443, 8443, 7443, 8444}

HTTP_ENUM_PORTS = {
    80, 443, 8080, 8443, 8888, 3000, 5000, 9090,
    81, 593, 3001, 4200, 7080, 7443, 8008, 8082, 8083, 8088, 8090, 8444,
}


def _scheme_for_port(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


def _other_scheme(scheme: str) -> str:
    return "http" if scheme == "https" else "https"


def _probe_safe(host: str, port: int, scheme: str, timeout_ms: int) -> HttpEnumResult:
    try:
        return probe(host, port, scheme, timeout_ms)
    except Exception as exc:
        return HttpEnumResult(host=host, port=port, scheme=scheme, error=str(exc))


def plan_checks(scan_results: List[ScanResult]):
    planned = []
    for scan_result in scan_results:
        if not scan_result.host.alive:
            continue
        for port_result in scan_result.open_ports():
            if port_result.protocol != Protocol.TCP:
                continue
            if port_result.port not in HTTP_ENUM_PORTS:
                continue
            planned.append((scan_result.host.ip, port_result))
    return planned


def run(scan_results: List[ScanResult], options: Optional[dict] = None, logger=None) -> List[HttpEnumResult]:
    options = options or {}
    try:
        timeout_ms = int(options.get("TIMEOUT", options.get("timeout", 3000)))
    except (TypeError, ValueError):
        timeout_ms = 3000

    results: List[HttpEnumResult] = []
    planned = plan_checks(scan_results)

    if not planned:
        if logger:
            logger.info("http_enum requested but no matching open HTTP port(s) were found")
        return results

    if logger:
        logger.info(f"Running http_enum on {len(planned)} open port(s)")

    for host_ip, port_result in planned:
        port = port_result.port
        scheme = _scheme_for_port(port)
        if logger:
            logger.info(f"Probing {scheme}://{host_ip}:{port}")
        result = _probe_safe(host_ip, port, scheme, timeout_ms)

        if result.error is not None:
            fallback_scheme = _other_scheme(scheme)
            if logger:
                logger.info(f"{scheme}://{host_ip}:{port} failed ({result.error}), retrying as {fallback_scheme}")
            fallback_result = _probe_safe(host_ip, port, fallback_scheme, timeout_ms)
            if fallback_result.error is None:
                result = fallback_result

        results.append(result)

    return results
