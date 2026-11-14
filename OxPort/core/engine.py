import ipaddress
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

import yaml

from core import exporter
from core.dns_resolver import (
    build_target_list,
    expand_cidr,
    expand_excludes,
    get_scan_source,
    load_hosts_grouped_by_subnet_from_file,
    load_subnets_from_file,
    load_targets_from_file,
    reverse_resolve_many,
)
from core.logger import get_logger
from core.os_profiles import get_os_ports
from core.models import (
    DiscoveryMethod,
    Host,
    PortResult,
    PortState,
    Protocol,
    ScanConfig,
    ScanProfile,
    ScanResult,
    ScanTechnique,
)
from core.threads import RateLimiter, ThreadedExecutor, split_into_ranges
from modules.detection import os_fingerprint, service_detect, version_probe
from modules.host.discovery import discover_hosts, discover_hosts_ranged, discover_hosts_staged, probe_host
from modules.scanner import stealth, tcp_connect, tcp_syn, udp_scan

_RULES_PATH_TEMPLATE = "rules/{name}.yaml"
_CACHE_FILE = "scan.cache"

_STEALTH_TECHNIQUES = {ScanTechnique.FIN, ScanTechnique.NULL, ScanTechnique.XMAS, ScanTechnique.ACK}


def _host_to_dict(host: Host) -> dict:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "alive": host.alive,
        "discovery_method": host.discovery_method.value,
        "mac": host.mac,
        "ttl_observed": host.ttl_observed,
        "reason": host.reason,
        "os_hint": host.os_hint,
    }


def _dict_to_host(data: dict) -> Host:
    return Host(
        ip=data["ip"],
        hostname=data.get("hostname"),
        alive=bool(data.get("alive", False)),
        discovery_method=DiscoveryMethod(data.get("discovery_method", "none")),
        mac=data.get("mac"),
        ttl_observed=data.get("ttl_observed"),
        reason=data.get("reason"),
        os_hint=data.get("os_hint"),
    )


def _save_scan_cache(subnets_file: str, subnet_results: List[Tuple[str, List[Host]]]) -> None:
    data = {
        "subnets_file": os.path.abspath(subnets_file),
        "completed_subnets": [subnet for subnet, _ in subnet_results],
        "results": [
            {"subnet": subnet, "hosts": [_host_to_dict(h) for h in hosts]}
            for subnet, hosts in subnet_results
        ],
    }
    with open(_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _load_scan_cache() -> Tuple[str, List[Tuple[str, List[Host]]]]:
    with open(_CACHE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    subnet_results = [
        (entry["subnet"], [_dict_to_host(h) for h in entry["hosts"]])
        for entry in data.get("results", [])
    ]
    return data.get("subnets_file", ""), subnet_results


def load_profile(name: str) -> ScanProfile:
    path = _RULES_PATH_TEMPLATE.format(name=name)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ScanProfile.from_dict(name, data)


def parse_port_spec(spec: str, all_ports: bool) -> List[int]:
    if all_ports:
        return list(range(1, 65536))

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-")
            start, end = int(start_str), int(end_str)
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    return sorted(ports)


def _scan_single_port(ip: str, port: int, technique: ScanTechnique, timeout_ms: int) -> PortResult:
    if technique == ScanTechnique.CONNECT:
        return tcp_connect.scan_port(ip, port, timeout_ms)
    if technique == ScanTechnique.SYN:
        return tcp_syn.scan_port(ip, port, timeout_ms)
    if technique == ScanTechnique.UDP:
        return udp_scan.scan_port(ip, port, timeout_ms)
    if technique in _STEALTH_TECHNIQUES:
        return stealth.scan_port(ip, port, technique, timeout_ms)
    raise ValueError(f"unsupported technique: {technique}")


def _detect_single_port(host: Host, port_result: PortResult, config: ScanConfig) -> None:
    if port_result.state != PortState.OPEN:
        return

    protocol_str = port_result.protocol.value
    service_name = service_detect.identify_service(port_result.port, protocol_str)
    port_result.service_name = service_name

    if config.grab_banner or config.detect_version:
        if port_result.protocol == Protocol.TCP:
            banner = service_detect.grab_banner(host.ip, port_result.port)
            port_result.banner = banner

            if config.detect_version and service_name:
                version = version_probe.extract_version(service_name, banner)
                port_result.version = version


def _on_host_result(config: ScanConfig, progress: Optional["exporter.LiveProgress"] = None):
    def handler(host: Host) -> None:
        if progress:
            progress.tick()

        if not host.alive:
            return
        if config.live:
            if progress:
                progress.report_row(exporter.format_live_host_row(host))
            else:
                exporter.print_live_host(host)

    return handler


def _on_port_result(host: Host, config: ScanConfig, progress: Optional["exporter.LiveProgress"] = None):
    def handler(port_result: PortResult) -> None:
        if progress:
            progress.tick()

        if port_result.state != PortState.OPEN:
            return
        _detect_single_port(host, port_result, config)
        if config.live:
            row = exporter.format_live_port_row(host.ip, port_result)
            if row is None:
                return
            if progress:
                progress.report_row(row)
            else:
                exporter.print_live_port(host.ip, port_result)

    return handler


def _scan_host_ports(host: Host, ports: List[int], techniques: List[ScanTechnique],
                      profile: ScanProfile, config: ScanConfig,
                      progress: Optional["exporter.LiveProgress"] = None) -> List[PortResult]:
    logger = get_logger()
    results: List[PortResult] = []
    threads = config.threads or profile.threads
    rate = config.rate if config.rate is not None else profile.rate

    executor = ThreadedExecutor(max_workers=threads, rate_per_second=rate, jitter_ms=profile.jitter_ms)
    on_result = _on_port_result(host, config, progress)

    for technique in techniques:
        logger.debug(f"Scanning {host.ip} with technique={technique.value} on {len(ports)} port(s)")
        technique_results = executor.run(
            lambda port: _scan_single_port(host.ip, port, technique, profile.timeout_ms),
            ports,
            on_result=on_result,
        )
        results.extend(technique_results)

    return results


def _scan_host_ports_ranged(host: Host, ports: List[int], techniques: List[ScanTechnique],
                             profile: ScanProfile, config: ScanConfig,
                             progress: Optional["exporter.LiveProgress"] = None) -> List[PortResult]:
    logger = get_logger()
    n_threads = config.threads
    chunks = split_into_ranges(ports, n_threads)

    logger.debug(f"Splitting {len(ports)} port(s) across {len(chunks)} thread(s) for {exporter.highlight_target(host.ip)}")
    for idx, chunk in enumerate(chunks, start=1):
        if chunk:
            logger.debug(f"  thread {idx}: ports {chunk[0]}-{chunk[-1]} ({len(chunk)} port(s))")

    rate = config.rate if config.rate is not None else profile.rate
    rate_limiter = RateLimiter(rate)
    on_result = _on_port_result(host, config, progress)

    results: List[PortResult] = []
    results_lock = threading.Lock()

    def _worker(chunk: List[int]) -> None:
        local_results: List[PortResult] = []
        for port in chunk:
            for technique in techniques:
                rate_limiter.wait()
                port_result = _scan_single_port(host.ip, port, technique, profile.timeout_ms)
                on_result(port_result)
                local_results.append(port_result)

        with results_lock:
            results.extend(local_results)

    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [pool.submit(_worker, chunk) for chunk in chunks]
        for future in futures:
            future.result()

    return results


def _apply_os_detection(host: Host, config: ScanConfig):
    if config.detect_os and host.ttl_observed:
        return os_fingerprint.guess_os(host.ttl_observed)
    return None


def run_staged_subnet_discovery(config: ScanConfig) -> List[ScanResult]:
    logger = get_logger()
    profile = load_profile(config.profile_name)

    subnets = load_subnets_from_file(config.subnets_file)
    if not subnets:
        logger.error("No subnets found in the subnets file, aborting")
        return []

    if config.only_host:
        logger.info("--only-host set: no port scan will be performed on any host")

    initial_results: List[Tuple[str, List[Host]]] = []

    if config.resume:
        if os.path.exists(_CACHE_FILE):
            cached_subnets_file, initial_results = _load_scan_cache()
            completed = {subnet for subnet, _ in initial_results}

            if cached_subnets_file and cached_subnets_file != os.path.abspath(config.subnets_file):
                logger.warning(
                    f"{_CACHE_FILE} was created for a different subnets file ({cached_subnets_file}); "
                    f"resuming anyway against {config.subnets_file}"
                )

            skipped = [s for s in subnets if s in completed]
            subnets = [s for s in subnets if s not in completed]
            logger.info(
                f"--resume: {len(skipped)}/{len(skipped) + len(subnets)} subnet(s) already completed "
                f"in {_CACHE_FILE}, continuing with {len(subnets)} remaining subnet(s)"
            )
        else:
            logger.warning(f"--resume set but no {_CACHE_FILE} found, starting a fresh scan")

    if not subnets:
        logger.info("Nothing left to scan, every subnet was already completed")
        subnet_results = initial_results
    else:
        logger.info(
            f"{len(subnets)} subnet(s) to process; processing one subnet at a time, each fully "
            f"finished before the next one starts"
        )

        threads = config.threads or profile.threads

        on_subnet_start = None
        host_live_handler = None

        if config.live:
            host_live_handler = _on_host_result(config)
            subnet_counter = {"index": 0}

            def on_subnet_start(subnet: str) -> None:
                if subnet_counter["index"] > 0:
                    print("\n" * 3)
                print(subnet)
                exporter.print_live_hosts_header()
                subnet_counter["index"] += 1

        def on_interrupt(partial_results: List[Tuple[str, List[Host]]]) -> None:
            _save_scan_cache(config.subnets_file, partial_results)
            logger.warning(
                f"Scan interrupted by user: progress saved to {_CACHE_FILE} "
                f"({len(partial_results)} subnet(s) completed). Re-run with --resume to continue."
            )

        subnet_results = discover_hosts_staged(
            subnets, config, threads, profile.timeout_ms,
            on_subnet_start=on_subnet_start,
            on_result=host_live_handler,
            on_interrupt=on_interrupt,
            initial_results=initial_results,
        )

    if not config.live:
        exporter.print_staged_subnet_results(subnet_results)

    if os.path.exists(_CACHE_FILE):
        os.remove(_CACHE_FILE)
        logger.info(f"Scan fully completed: removed {_CACHE_FILE}")

    return [ScanResult(host=host) for _, hosts in subnet_results for host in hosts]


def _port_scan_hosts(alive_hosts: List[Host], config: ScanConfig, profile: ScanProfile) -> List[ScanResult]:
    logger = get_logger()

    if not alive_hosts:
        logger.warning("No alive hosts found, nothing to scan")
        return []

    if config.os_profile:
        ports = get_os_ports(config.os_profile)
        logger.info(f"OS profile '{config.os_profile}' selected: restricting scan to {len(ports)} OS-specific port(s)")
    else:
        ports = parse_port_spec(config.ports, config.all_ports)

    logger.info(f"Scanning {len(alive_hosts)} host(s) on {len(ports)} port(s) with techniques={[t.value for t in config.techniques]}")

    use_ranged_threads = bool(config.all_ports and config.threads)
    per_host_units = len(ports) * len(config.techniques)

    if config.live:
        exporter.print_live_header()

    results: List[ScanResult] = []

    for host in alive_hosts:
        start = time.monotonic()

        progress = None
        if config.live:
            progress = exporter.LiveProgress(per_host_units, label=host.ip)
            progress.start()

        try:
            if use_ranged_threads:
                port_results = _scan_host_ports_ranged(host, ports, config.techniques, profile, config, progress)
            else:
                port_results = _scan_host_ports(host, ports, config.techniques, profile, config, progress)
        finally:
            if progress:
                progress.finish(blank_lines=2)

        os_match = _apply_os_detection(host, config)

        duration = time.monotonic() - start
        results.append(ScanResult(host=host, ports=port_results, os_match=os_match, scan_duration_s=round(duration, 2)))

    return results


def run_subnets_file_direct_scan(config: ScanConfig) -> List[ScanResult]:
    """-i/--subnets-file combined with -Pn/--skip-discovery: skip the staged,
    discovery-only mode entirely and go straight to port scanning exactly the hosts
    found in the file.

    Each line is read literally: a line with a "/" (e.g. 10.0.40.0/24) is expanded as a
    subnet, a bare IP (e.g. 10.0.222.5) is treated as that one single host, NOT auto
    expanded to a /24 (unlike the staged-discovery mode, where a subnets file always
    means subnets to discover).

    Before committing to a full port scan (which can be tens of thousands of ports per
    host), each target still gets one quick liveness probe (ARP/ICMP/TCP-ping, same
    methods as normal discovery, run in parallel across all targets). A target that
    doesn't answer is skipped and the scan moves on to the next one; -Pn here means
    "skip the staged discovery stage", not "blindly trust every line in the file"."""
    logger = get_logger()
    profile = load_profile(config.profile_name)

    raw_lines = load_targets_from_file(config.subnets_file)
    if not raw_lines:
        logger.error("No hosts/subnets found in the subnets file, aborting")
        return []

    excluded = expand_excludes(config.exclude_raw)

    target_set = set()
    for line in raw_lines:
        if "/" in line:
            target_set.update(expand_cidr(line))
        else:
            target_set.add(line)
    targets = sorted(target_set - excluded, key=lambda ip: ipaddress.ip_address(ip))

    if not targets:
        logger.error("No valid targets resolved from the subnets file, aborting")
        return []

    logger.info(
        f"-i/--subnets-file + -Pn: checking liveness of {len(targets)} host(s) loaded from "
        f"{config.subnets_file} (quick probe, not a full discovery stage) before port scanning"
    )

    threads = config.threads or profile.threads
    progress = exporter.LiveProgress(len(targets), label="Liveness") if config.live else None
    host_live_handler = _on_host_result(config, progress)
    if config.live:
        exporter.print_live_hosts_header()
        if progress:
            progress.start()

    try:
        executor = ThreadedExecutor(max_workers=threads)
        probed_hosts = executor.run(
            lambda ip: probe_host(ip, config, profile.timeout_ms),
            targets,
            on_result=host_live_handler,
        )
    finally:
        if progress:
            progress.finish(blank_lines=1)

    alive_hosts = sorted([h for h in probed_hosts if h.alive], key=lambda h: ipaddress.ip_address(h.ip))
    skipped_count = len(probed_hosts) - len(alive_hosts)

    hostname_map = reverse_resolve_many([h.ip for h in alive_hosts], threads=threads)
    for host in alive_hosts:
        host.hostname = hostname_map.get(host.ip)

    if skipped_count:
        logger.info(f"{skipped_count}/{len(targets)} host(s) did not respond, skipped")

    if not alive_hosts:
        logger.warning("No alive hosts found, nothing to scan")
        return [ScanResult(host=h) for h in probed_hosts]

    logger.info(f"{len(alive_hosts)}/{len(targets)} host(s) alive, proceeding to port scan")

    return _port_scan_hosts(alive_hosts, config, profile)


def run_subnets_file_grouped_port_scan(config: ScanConfig) -> List[ScanResult]:
    logger = get_logger()
    profile = load_profile(config.profile_name)

    grouped = load_hosts_grouped_by_subnet_from_file(config.subnets_file)
    if not grouped:
        logger.error("No hosts/subnets found in the subnets file, aborting")
        return []

    excluded = expand_excludes(config.exclude_raw)
    os.makedirs(config.output_dir, exist_ok=True)

    threads = config.threads or profile.threads
    ordered_subnets = sorted(grouped.keys(), key=lambda s: ipaddress.ip_network(s).network_address)

    all_results: List[ScanResult] = []

    for subnet in ordered_subnets:
        targets = sorted(set(grouped[subnet]) - excluded, key=lambda ip: ipaddress.ip_address(ip))
        if not targets:
            continue

        logger.info(f"Subnet {subnet}: checking liveness of {len(targets)} host(s)")

        progress = exporter.LiveProgress(len(targets), label=subnet) if config.live else None
        host_live_handler = _on_host_result(config, progress)
        if config.live:
            exporter.print_live_hosts_header()
            if progress:
                progress.start()

        try:
            executor = ThreadedExecutor(max_workers=threads)
            probed_hosts = executor.run(
                lambda ip: probe_host(ip, config, profile.timeout_ms),
                targets,
                on_result=host_live_handler,
            )
        finally:
            if progress:
                progress.finish(blank_lines=1)

        alive_hosts = sorted([h for h in probed_hosts if h.alive], key=lambda h: ipaddress.ip_address(h.ip))
        skipped_count = len(probed_hosts) - len(alive_hosts)

        hostname_map = reverse_resolve_many([h.ip for h in alive_hosts], threads=threads)
        for host in alive_hosts:
            host.hostname = hostname_map.get(host.ip)

        if skipped_count:
            logger.info(f"Subnet {subnet}: {skipped_count}/{len(targets)} host(s) did not respond, skipped")

        subnet_results = _port_scan_hosts(alive_hosts, config, profile) if alive_hosts else []
        all_results.extend(subnet_results)

        file_name = subnet.replace("/", "-") + "_ports.json"
        output_path = os.path.join(config.output_dir, file_name)

        template_meta = {
            "mode": "port_scan",
            "threads": config.threads,
            "port_scan": True,
            "host_scan": False,
            "host_ip": get_scan_source(targets[0]),
            "subnets": [subnet],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            exporter.export_template(subnet_results, f, template_meta)

        logger.info(f"Subnet {subnet}: {len(subnet_results)} host(s) scanned, results written to {output_path}")

    return all_results


def run(config: ScanConfig) -> List[ScanResult]:
    logger = get_logger()

    if config.subnets_file:
        if config.output_dir:
            return run_subnets_file_grouped_port_scan(config)
        if config.skip_discovery:
            return run_subnets_file_direct_scan(config)
        return run_staged_subnet_discovery(config)

    profile = load_profile(config.profile_name)

    targets = build_target_list(
        host=config.targets_raw[0] if config.targets_raw else None,
        cidr=config.cidr,
        ip_range=config.ip_range,
        input_file=config.input_file,
        exclude=config.exclude_raw,
    )

    if not targets:
        logger.error("No valid targets resolved, aborting")
        return []

    discovery_only = bool(config.ping_only or config.only_host or config.cidr)
    discovery_threads = config.threads or profile.threads
    use_ranged_hosts = bool(config.cidr and config.threads)

    progress = exporter.LiveProgress(len(targets), label="Discovery") if config.live else None
    host_live_handler = _on_host_result(config, progress)

    def header_printer() -> None:
        exporter.print_live_hosts_header()
        if progress:
            progress.start()

    if config.cidr and discovery_only:
        logger.info("CIDR target detected: host discovery only, port scan will be skipped")

    try:
        if use_ranged_hosts:
            logger.debug(
                f"CIDR target with --threads={config.threads}: splitting discovery into "
                f"{config.threads} contiguous, non-overlapping host range(s)"
            )
            hosts = discover_hosts_ranged(targets, config, config.threads, profile.timeout_ms,
                                           on_result=host_live_handler,
                                           on_start=header_printer if progress else None)
        else:
            hosts = discover_hosts(targets, config, discovery_threads, profile.timeout_ms,
                                    on_result=host_live_handler,
                                    on_start=header_printer if progress else None)
    finally:
        if progress:
            progress.finish(blank_lines=1)

    alive_hosts = [h for h in hosts if h.alive]

    if discovery_only:
        return [ScanResult(host=h) for h in hosts]

    return _port_scan_hosts(alive_hosts, config, profile)
