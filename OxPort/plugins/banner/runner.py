from typing import List, Optional

from core.models import PortResult, PortState, Protocol, ScanResult
from plugins.banner import (
    ftp_banner,
    http_banner,
    rdp_banner,
    smb_banner,
    smtp_banner,
    ssh_banner,
)
from plugins.banner.base import BannerResult

MODULES = {
    "ftp": ftp_banner,
    "http": http_banner,
    "rdp": rdp_banner,
    "smb": smb_banner,
    "smtp": smtp_banner,
    "ssh": ssh_banner,
}

_SERVICE_NAME_TO_KEY = {
    "FTP": "ftp",
    "HTTP": "http",
    "HTTP-ALT": "http",
    "HTTP-PROXY": "http",
    "RDP": "rdp",
    "MS-WBT-SERVER": "rdp",
    "SMB": "smb",
    "NETBIOS-SSN": "smb",
    "SMTP": "smtp",
    "SMTP-SUBMISSION": "smtp",
    "SMTPS": "smtp",
    "SSH": "ssh",
}

_PORT_FALLBACK = {
    21: "ftp",
    80: "http",
    8080: "http",
    8443: "http",
    8008: "http",
    3389: "rdp",
    139: "smb",
    445: "smb",
    25: "smtp",
    465: "smtp",
    587: "smtp",
    22: "ssh",
}


def _service_key_for_port(port_result: PortResult) -> Optional[str]:
    service_name = (port_result.service_name or "").upper()
    if service_name in _SERVICE_NAME_TO_KEY:
        return _SERVICE_NAME_TO_KEY[service_name]
    return _PORT_FALLBACK.get(port_result.port)


def plan_checks(scan_results: List[ScanResult]):
    planned = []
    for scan_result in scan_results:
        if not scan_result.host.alive:
            continue
        for port_result in scan_result.open_ports():
            if port_result.protocol != Protocol.TCP:
                continue
            service_key = _service_key_for_port(port_result)
            if service_key is None:
                continue
            planned.append((scan_result.host.ip, port_result, service_key))
    return planned


def run(scan_results: List[ScanResult], options: Optional[dict] = None, logger=None) -> List[BannerResult]:
    options = options or {}
    try:
        timeout_ms = int(options.get("TIMEOUT", options.get("timeout", 3000)))
    except (TypeError, ValueError):
        timeout_ms = 3000

    results: List[BannerResult] = []
    planned = plan_checks(scan_results)

    if not planned:
        if logger:
            logger.info("Banner grabbing requested but no matching open ports (ftp/http/rdp/smb/smtp/ssh) were found")
        return results

    if logger:
        logger.info(f"Running banner grab on {len(planned)} open port(s)")

    for host_ip, port_result, service_key in planned:
        module = MODULES[service_key]
        if logger:
            logger.info(f"Grabbing banner: {service_key} on {host_ip}:{port_result.port}")
        try:
            result = module.check(host_ip, port_result.port, timeout_ms)
        except Exception as exc:
            result = BannerResult(
                service=service_key,
                host=host_ip,
                port=port_result.port,
                protocol=port_result.protocol.value,
                banner=None,
                detail="check could not complete",
                error=str(exc),
            )
        results.append(result)

    return results
