import csv
import ipaddress
import itertools
import json
import os
import sys
import tempfile
import threading
import time
import zipfile
from typing import List, Optional, TextIO

from core.models import ScanResult
from core.os_profiles import classify_port

_BRIGHT_BLUE = "\033[94m"
_BRIGHT_ORANGE = "\033[38;5;208m"
_BRIGHT_GREEN = "\033[92m"
_LIGHT_BLUE = "\033[38;5;117m"
_BRIGHT_PINK = "\033[38;5;213m"
_DARK_PINK = "\033[38;5;162m"
_GRAY = "\033[38;5;244m"
_PURPLE = "\033[38;5;135m"
_RESET = "\033[0m"

_GUESS_COLOR_MAP = {
    "windows": _LIGHT_BLUE,
    "linux": _BRIGHT_PINK,
    "both": _PURPLE,
    "other": _GRAY,
}


def _colors_enabled(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{_RESET}"


def highlight_target(text: str, stream: TextIO = sys.stdout) -> str:
    return _colorize(text, _BRIGHT_BLUE, _colors_enabled(stream))


_LIVE_TARGET_WIDTH = 16
_LIVE_PORT_WIDTH = 7
_LIVE_STATUS_WIDTH = 11


def _format_port_row(host_ip: str, port, target_width: int, port_width: int, status_width: int, colors: bool) -> Optional[str]:
    if port.state.value not in ("open", "open|filtered"):
        return None

    status = _STATUS_LABEL.get(port.state.value, port.state.value)
    guess = port.service_name or port.version or ""

    target_field = _colorize(f"{host_ip:<{target_width}}", _BRIGHT_BLUE, colors)
    port_field = _colorize(f"{port.port:<{port_width}}", _BRIGHT_ORANGE, colors)
    status_color = _BRIGHT_GREEN if port.state.value == "open" else None
    status_field = _colorize(f"{status:<{status_width}}", status_color, colors) if status_color else f"{status:<{status_width}}"

    os_class = classify_port(port.port, port.protocol.value)
    guess_field = _colorize(guess, _GUESS_COLOR_MAP[os_class], colors)

    return f"{target_field}{port_field}{status_field}{guess_field}"


def print_live_header(stream: TextIO = sys.stdout) -> None:
    header = f"{'TARGET':<{_LIVE_TARGET_WIDTH}}{'PORT':<{_LIVE_PORT_WIDTH}}{'STATUS':<{_LIVE_STATUS_WIDTH}}{'GUESS'}"
    stream.write(header + "\n")
    stream.flush()


def print_live_port(host_ip: str, port, stream: TextIO = sys.stdout) -> None:
    row = format_live_port_row(host_ip, port, stream)
    if row is None:
        return
    stream.write(row + "\n")
    stream.flush()


def format_live_port_row(host_ip: str, port, stream: TextIO = sys.stdout) -> Optional[str]:
    colors = _colors_enabled(stream)
    return _format_port_row(host_ip, port, _LIVE_TARGET_WIDTH, _LIVE_PORT_WIDTH, _LIVE_STATUS_WIDTH, colors)


class LiveProgress:
    _SPINNER = "|/-\\"
    _BAR_WIDTH = 30
    _MIN_REDRAW_INTERVAL_S = 0.1

    def __init__(self, total: int, stream: TextIO = sys.stdout, label: str = "Overall"):
        self.total = max(1, total)
        self.stream = stream
        self.label = label
        self._lock = threading.Lock()
        self._done = 0
        self._active = False
        self._last_draw = 0.0
        self._spin = itertools.cycle(self._SPINNER)
        self._enabled = hasattr(stream, "isatty") and stream.isatty()
        self._colors = _colors_enabled(stream)

    def start(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._active = True
            self._redraw(force=True)

    def tick(self, n: int = 1) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._done = min(self._done + n, self.total)
            self._redraw()

    def report_row(self, row: str) -> None:
        with self._lock:
            if self._active:
                self.stream.write("\r\x1b[2K")
            self.stream.write(row + "\n")
            if self._active:
                self._redraw(force=True)
            self.stream.flush()

    def finish(self, blank_lines: int = 0) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._done = self.total
            self._redraw(force=True)
            self.stream.write("\n" * (1 + blank_lines))
            self._active = False
            self.stream.flush()

    def _bar_text(self) -> str:
        pct = (self._done / self.total) * 100.0
        filled = int(self._BAR_WIDTH * pct / 100)
        bar = "#" * filled + "." * (self._BAR_WIDTH - filled)
        spin = " " if self._done >= self.total else next(self._spin)
        label = f"{_colorize(self.label, _BRIGHT_BLUE, self._colors)}: " if self.label else ""
        return f"{label}[{bar}] {pct:5.1f}%  {self._done}/{self.total} {spin}"

    def _redraw(self, force: bool = False) -> None:
        if not self._active:
            return
        now = time.monotonic()
        if not force and (now - self._last_draw) < self._MIN_REDRAW_INTERVAL_S:
            return
        self._last_draw = now
        self.stream.write("\r\x1b[2K" + self._bar_text())
        self.stream.flush()


_LIVE_HOST_TARGET_WIDTH = 16
_LIVE_HOST_STATUS_WIDTH = 11
_LIVE_HOST_TYPE_WIDTH = 8
_LIVE_HOST_OS_WIDTH = 10

_DISCOVERY_TYPE_LABEL = {
    "tcp_ping": "TCP",
    "arp": "ARP",
    "icmp": "ICMP",
    "skipped": "SKIPPED",
    "none": "NONE",
}


def print_live_hosts_header(stream: TextIO = sys.stdout) -> None:
    header = (
        f"{'TARGET':<{_LIVE_HOST_TARGET_WIDTH}}"
        f"{'STATUS':<{_LIVE_HOST_STATUS_WIDTH}}"
        f"{'TYPE':<{_LIVE_HOST_TYPE_WIDTH}}"
        f"{'OS':<{_LIVE_HOST_OS_WIDTH}}"
        f"REASON"
    )
    stream.write(header + "\n")
    stream.flush()


def format_live_host_row(host, stream: TextIO = sys.stdout) -> str:
    colors = _colors_enabled(stream)
    target_field = _colorize(f"{host.ip:<{_LIVE_HOST_TARGET_WIDTH}}", _BRIGHT_BLUE, colors)
    status_field = _colorize(f"{'LIVE':<{_LIVE_HOST_STATUS_WIDTH}}", _BRIGHT_GREEN, colors)
    type_label = _DISCOVERY_TYPE_LABEL.get(host.discovery_method.value, host.discovery_method.value.upper())
    type_field = _colorize(f"{type_label:<{_LIVE_HOST_TYPE_WIDTH}}", _BRIGHT_ORANGE, colors)
    os_label = host.os_hint or "-"
    os_color = (
        _LIGHT_BLUE if os_label == "Windows"
        else _BRIGHT_PINK if os_label == "Linux"
        else _DARK_PINK if os_label == "Network"
        else None
    )
    os_field = _colorize(f"{os_label:<{_LIVE_HOST_OS_WIDTH}}", os_color, colors) if os_color else f"{os_label:<{_LIVE_HOST_OS_WIDTH}}"
    reason_field = host.reason or ""
    return f"{target_field}{status_field}{type_field}{os_field}{reason_field}"


def print_live_host(host, stream: TextIO = sys.stdout) -> None:
    stream.write(format_live_host_row(host, stream) + "\n")
    stream.flush()


def print_staged_subnet_results(subnet_results, stream: TextIO = sys.stdout) -> None:
    for index, (subnet, hosts) in enumerate(subnet_results):
        if index > 0:
            stream.write("\n" * 4)

        stream.write(subnet + "\n")
        print_live_hosts_header(stream)
        for host in hosts:
            if host.alive:
                print_live_host(host, stream)

    stream.flush()


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "ip": result.host.ip,
        "hostname": result.host.hostname,
        "alive": result.host.alive,
        "discovery_method": result.host.discovery_method.value,
        "os_match": {
            "name": result.os_match.name,
            "confidence": result.os_match.confidence,
            "family": result.os_match.family,
        } if result.os_match else None,
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol.value,
                "state": p.state.value,
                "service": p.service_name,
                "version": p.version,
                "banner": p.banner,
                "response_time_ms": p.response_time_ms,
            }
            for p in result.ports
        ],
        "scan_duration_s": result.scan_duration_s,
    }


def export_json(results: List[ScanResult], stream: TextIO):
    data = [_result_to_dict(r) for r in results]
    json.dump(data, stream, indent=2)
    stream.write("\n")


def export_csv(results: List[ScanResult], stream: TextIO):
    writer = csv.writer(stream)
    writer.writerow(["ip", "hostname", "port", "protocol", "state", "service", "version", "banner"])
    for result in results:
        for p in result.open_ports():
            writer.writerow([
                result.host.ip,
                result.host.hostname or "",
                p.port,
                p.protocol.value,
                p.state.value,
                p.service_name or "",
                p.version or "",
                p.banner or "",
            ])


_STATUS_LABEL = {
    "open": "REACHABLE",
    "closed": "UNREACHABLE",
    "filtered": "NO-RESPONSE",
    "open|filtered": "UNCERTAIN",
    "unfiltered": "UNREACHABLE",
}


def export_txt(results: List[ScanResult], stream: TextIO):
    target_width = max([len("TARGET")] + [len(r.host.ip) for r in results]) + 2
    port_width = 7
    status_width = 11

    colors = _colors_enabled(stream)

    header = f"{'TARGET':<{target_width}}{'PORT':<{port_width}}{'STATUS':<{status_width}}{'GUESS'}"
    stream.write(header + "\n")

    row_count = 0
    for result in results:
        for p in sorted(result.ports, key=lambda x: x.port):
            row = _format_port_row(result.host.ip, p, target_width, port_width, status_width, colors)
            if row is None:
                continue
            stream.write(row + "\n")
            row_count += 1
            if p.banner:
                stream.write(f"{'':<{target_width}}{'':<{port_width}}banner: {p.banner}\n")

    if row_count == 0:
        stream.write("no reachable ports on any target\n")

    for result in results:
        if result.os_match:
            stream.write(f"\n{result.host.ip} os guess: {result.os_match.name} ({result.os_match.confidence:.0f}% confidence)\n")


def _port_to_template_dict(p) -> dict:
    return {
        "port": p.port,
        "protocol": p.protocol.value,
        "status": p.state.value,
        "service": p.service_name,
        "version": p.version,
        "banner": p.banner,
        "notes": None,
    }


def _host_to_template_entry(result: ScanResult, include_ports: bool) -> dict:
    host = result.host

    os_name = None
    if result.os_match:
        os_name = result.os_match.name
    elif host.os_hint:
        os_name = host.os_hint

    return {
        "host": host.ip,
        "ports": [_port_to_template_dict(p) for p in result.open_ports()] if include_ports else [],
        "os": os_name,
        "type": host.discovery_method.value,
        "reason": host.reason,
        "notes": None,
    }


def export_template(results: List[ScanResult], stream: TextIO, template_meta: Optional[dict] = None) -> None:
    meta = template_meta or {}
    mode = meta.get("mode")
    port_scan = bool(meta.get("port_scan"))
    host_scan = bool(meta.get("host_scan"))

    alive_results = [r for r in results if r.host.alive]

    data = {
        "mode": mode,
        "threads": meta.get("threads"),
        "port_scan": port_scan,
        "host_scan": host_scan,
        "host_ip": meta.get("host_ip") or {"interface": None, "ip": None},
        "subnets": meta.get("subnets") or [],
        "hosts": [_host_to_template_entry(r, include_ports=port_scan) for r in alive_results],
    }

    json.dump(data, stream, indent=2)
    stream.write("\n")


def export_host_list_from_json(input_path: str, subnet: str, output_path: str) -> int:
    network = ipaddress.ip_network(subnet, strict=False)

    with open(input_path, "r") as f:
        data = json.load(f)

    ips = []
    for entry in data.get("hosts", []):
        ip = entry.get("host")
        if not ip:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr in network:
            ips.append(ip)

    ips = sorted(set(ips), key=lambda ip: ipaddress.ip_address(ip))

    with open(output_path, "w") as f:
        for ip in ips:
            f.write(ip + "\n")

    return len(ips)


def export_host_lists_by_subnet_zip(input_path: str, zip_path: str) -> int:
    with open(input_path, "r") as f:
        data = json.load(f)

    subnets = data.get("subnets", [])
    hosts = data.get("hosts", [])

    with tempfile.TemporaryDirectory() as tmp_dir:
        file_paths = []
        for subnet in subnets:
            network = ipaddress.ip_network(subnet, strict=False)
            ips = []
            for entry in hosts:
                ip = entry.get("host")
                if not ip:
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if addr in network:
                    ips.append(ip)

            ips = sorted(set(ips), key=lambda ip: ipaddress.ip_address(ip))

            file_name = subnet.replace("/", "-") + ".txt"
            file_path = os.path.join(tmp_dir, file_name)
            with open(file_path, "w") as out:
                for ip in ips:
                    out.write(ip + "\n")
            file_paths.append(file_path)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in file_paths:
                zf.write(file_path, os.path.basename(file_path))

    return len(file_paths)


_ANON_TARGET_WIDTH = 16
_ANON_PORT_WIDTH = 7
_ANON_SERVICE_WIDTH = 10
_ANON_STATUS_WIDTH = 14


def print_anonymous_results(results, stream: TextIO = sys.stdout) -> None:
    if not results:
        return

    colors = _colors_enabled(stream)

    header = (
        f"{'TARGET':<{_ANON_TARGET_WIDTH}}"
        f"{'PORT':<{_ANON_PORT_WIDTH}}"
        f"{'SERVICE':<{_ANON_SERVICE_WIDTH}}"
        f"{'RESULT':<{_ANON_STATUS_WIDTH}}DETAIL"
    )
    stream.write("\n" + header + "\n")

    for result in results:
        if result.error:
            status = "ERROR"
            status_color = None
        elif result.vulnerable:
            status = "ANONYMOUS"
            status_color = _BRIGHT_GREEN if colors else None
        else:
            status = "PROTECTED"
            status_color = None

        target_field = _colorize(f"{result.host:<{_ANON_TARGET_WIDTH}}", _BRIGHT_BLUE, colors)
        port_field = _colorize(f"{result.port:<{_ANON_PORT_WIDTH}}", _BRIGHT_ORANGE, colors)
        service_field = f"{result.service.upper():<{_ANON_SERVICE_WIDTH}}"
        status_text = f"{status:<{_ANON_STATUS_WIDTH}}"
        status_field = _colorize(status_text, status_color, colors) if status_color else status_text
        detail_field = result.error if result.error else result.detail

        stream.write(f"{target_field}{port_field}{service_field}{status_field}{detail_field}\n")

    stream.flush()


_HTTP_TARGET_WIDTH = 16
_HTTP_PORT_WIDTH = 7
_HTTP_SCHEME_WIDTH = 7
_HTTP_STATUS_WIDTH = 8
_HTTP_TITLE_WIDTH = 34
_HTTP_SERVER_WIDTH = 22


def print_http_enum_results(results, stream: TextIO = sys.stdout) -> None:
    if not results:
        return

    colors = _colors_enabled(stream)

    stream.write("\nHTTP ENUMERATION RESULTS\n")
    header = (
        f"{'TARGET':<{_HTTP_TARGET_WIDTH}}"
        f"{'PORT':<{_HTTP_PORT_WIDTH}}"
        f"{'SCHEME':<{_HTTP_SCHEME_WIDTH}}"
        f"{'STATUS':<{_HTTP_STATUS_WIDTH}}"
        f"{'TITLE':<{_HTTP_TITLE_WIDTH}}"
        f"{'SERVER':<{_HTTP_SERVER_WIDTH}}EXTRA"
    )
    stream.write(header + "\n")

    for result in results:
        target_field = _colorize(f"{result.host:<{_HTTP_TARGET_WIDTH}}", _BRIGHT_BLUE, colors)
        port_field = _colorize(f"{result.port:<{_HTTP_PORT_WIDTH}}", _BRIGHT_ORANGE, colors)
        scheme_field = f"{result.scheme:<{_HTTP_SCHEME_WIDTH}}"

        if result.error:
            status_field = f"{'ERROR':<{_HTTP_STATUS_WIDTH}}"
            title_field = f"{'':<{_HTTP_TITLE_WIDTH}}"
            server_field = f"{'':<{_HTTP_SERVER_WIDTH}}"
            extra_field = result.error
        else:
            status_text = str(result.status_code) if result.status_code is not None else "?"
            status_color = _BRIGHT_GREEN if colors and result.status_code and result.status_code < 400 else None
            status_text_padded = f"{status_text:<{_HTTP_STATUS_WIDTH}}"
            status_field = _colorize(status_text_padded, status_color, colors) if status_color else status_text_padded

            title_text = (result.title or "")[:_HTTP_TITLE_WIDTH - 1]
            title_field = f"{title_text:<{_HTTP_TITLE_WIDTH}}"

            server_text = (result.server or "")[:_HTTP_SERVER_WIDTH - 1]
            server_field = f"{server_text:<{_HTTP_SERVER_WIDTH}}"

            extra_parts = []
            if result.location:
                extra_parts.append(f"Location: {result.location}")
            if result.powered_by:
                extra_parts.append(f"X-Powered-By: {result.powered_by}")
            other_tech = [t for t in result.technologies if t != result.server and t != result.powered_by]
            if other_tech:
                extra_parts.append(f"tech: {', '.join(other_tech)}")
            extra_field = " | ".join(extra_parts)

        stream.write(f"{target_field}{port_field}{scheme_field}{status_field}{title_field}{server_field}{extra_field}\n")

    stream.flush()


_MODBUS_LABEL_WIDTH = 24

# Identification objects already folded into "Device Name" - everything
# else from device_identification shows up under "Details" instead.
_MODBUS_NAME_FIELDS = ("ProductName", "ModelName", "VendorName", "ProductCode")


def _modbus_device_name(result) -> str:
    ident = result.device_identification
    if not ident:
        return ""

    if ident.get("ProductName"):
        return ident["ProductName"]
    if ident.get("ModelName"):
        return ident["ModelName"]

    vendor = ident.get("VendorName", "")
    product = ident.get("ProductCode", "")
    name = " ".join(part for part in (vendor, product) if part)
    return name


def _modbus_unit_line(result) -> str:
    if result.unit_id < 0:
        return "-"

    unit_text = f"0x{result.unit_id:02x}"
    if len(result.tested_unit_ids) > 1:
        others = [u for u in result.tested_unit_ids if u != result.unit_id]
        others_text = ", ".join(f"0x{u:02x}" for u in others)
        unit_text += f"  (also responded on {others_text} - unit id appears to be ignored)"
    return unit_text


def print_modbus_results(results, stream: TextIO = sys.stdout) -> None:
    if not results:
        return

    colors = _colors_enabled(stream)

    stream.write("\nMODBUS ENUMERATION RESULTS\n")
    stream.write("=" * 60 + "\n")

    for result in results:
        target_header = _colorize(f"{result.host}:{result.port}", _BRIGHT_BLUE, colors)
        stream.write(f"\n{target_header}\n")

        def label(text: str) -> str:
            padded = f"{text:<{_MODBUS_LABEL_WIDTH}}"
            return _colorize(padded, _BRIGHT_ORANGE, colors)

        if result.error:
            stream.write(f"  {label('Status:')}ERROR\n")
            stream.write(f"  {label('Details:')}{result.error}\n")
            continue

        if not result.responsive:
            stream.write(f"  {label('Status:')}NO RESPONSE\n")
            if result.notes:
                stream.write(f"  {label('Details:')}{' '.join(result.notes)}\n")
            continue

        status_text = _colorize("RESPONSIVE", _BRIGHT_GREEN, colors) if colors else "RESPONSIVE"
        stream.write(f"  {label('Status:')}{status_text}\n")
        stream.write(f"  {label('Unit:')}{_modbus_unit_line(result)}\n")

        device_name = _modbus_device_name(result)
        stream.write(f"  {label('Device Name:')}{device_name if device_name else '(unknown)'}\n")

        detail_parts = []
        extra_fields = {
            k: v for k, v in result.device_identification.items() if k not in _MODBUS_NAME_FIELDS
        }
        if extra_fields:
            detail_parts.append(", ".join(f"{k}={v}" for k, v in extra_fields.items()))
        if result.device_id_exception:
            detail_parts.append(f"device identification: {result.device_id_exception}")
        if result.report_slave_id_text:
            detail_parts.append(f"slave id data: {result.report_slave_id_text!r}")
        if result.report_slave_id_exception:
            detail_parts.append(f"report slave id: {result.report_slave_id_exception}")
        # The "unit id ignored" note is already reflected on the Unit: line
        # above, so don't repeat it here.
        other_notes = [n for n in result.notes if "unit id" not in n.lower()]
        if other_notes:
            detail_parts.extend(other_notes)

        stream.write(f"  {label('Details:')}{' | '.join(detail_parts) if detail_parts else '-'}\n")

        rp = result.register_probe
        if rp is not None:
            if rp.error:
                stream.write(f"  {label('Reg Probe:')}ERROR - {rp.error}\n")
            else:
                live = [e for e in rp.entries if e.responsive]
                if not live:
                    stream.write(f"  {label('Reg Probe:')}no live data returned\n")
                else:
                    for entry in rp.entries:
                        fc_label = f"FC{entry.fc:02d} {entry.name}"
                        if entry.error:
                            value = f"error: {entry.error}"
                        elif entry.exception:
                            value = f"exception: {entry.exception}"
                        elif entry.data_hex is not None:
                            value = f"live ({entry.data_hex if entry.data_hex else 'empty payload'})"
                        else:
                            value = "no response"
                        stream.write(f"  {label(fc_label + ':')}{value}\n")

        diag = result.diagnostics
        if diag is not None:
            if diag.error and not diag.responsive:
                stream.write(f"  {label('Diagnostics:')}ERROR - {diag.error}\n")
            elif diag.exception:
                stream.write(f"  {label('Diagnostics:')}exception: {diag.exception}\n")
            elif diag.echo_matched is not None:
                match_str = "echo OK" if diag.echo_matched else f"echo MISMATCH (got {diag.echo_received_hex})"
                lat_str = f"  latency {diag.latency_ms:.1f} ms" if diag.latency_ms is not None else ""
                stream.write(f"  {label('Diagnostics:')}{match_str}{lat_str}\n")

        es = result.exception_status
        if es is not None:
            if es.error and not es.responsive:
                stream.write(f"  {label('Exc Status:')}ERROR - {es.error}\n")
            elif es.exception:
                stream.write(f"  {label('Exc Status:')}exception: {es.exception}\n")
            elif es.status_byte is not None:
                stream.write(f"  {label('Exc Status:')}0x{es.status_byte:02x} ({es.status_bits})\n")

        fc_map = result.fc_capability_map
        if fc_map is not None:
            if fc_map.error and not fc_map.any_responsive:
                stream.write(f"  {label('FC Map:')}ERROR - {fc_map.error}\n")
            else:
                supported = [f"FC{e.fc:02X}" for e in fc_map.capabilities if e.result == "supported"]
                unsupported = [f"FC{e.fc:02X}" for e in fc_map.capabilities if e.result == "ILLEGAL FUNCTION"]
                stream.write(f"  {label('FC Map:')}supported=[{', '.join(supported) or 'none'}]"
                             f"  illegal=[{', '.join(unsupported) or 'none'}]\n")

        frp = result.file_record_probe
        if frp is not None:
            if frp.error and not frp.any_responsive:
                stream.write(f"  {label('File Record:')}ERROR - {frp.error}\n")
            else:
                live_fr = [e for e in frp.entries if e.responsive]
                if not live_fr:
                    stream.write(f"  {label('File Record:')}no data returned\n")
                else:
                    for e in live_fr:
                        loc = f"file={e.file_number} rec={e.record_number}"
                        val = e.exception if e.exception else f"data={e.data_hex}"
                        stream.write(f"  {label('File Record:')}{loc}  {val}\n")

        fifo = result.fifo_probe
        if fifo is not None:
            if fifo.error and not fifo.any_responsive:
                stream.write(f"  {label('FIFO Probe:')}ERROR - {fifo.error}\n")
            else:
                live_fi = [e for e in fifo.entries if e.responsive]
                if not live_fi:
                    stream.write(f"  {label('FIFO Probe:')}no data returned\n")
                else:
                    for e in live_fi:
                        if e.exception:
                            val = f"exception: {e.exception}"
                        else:
                            val = f"addr=0x{e.fifo_pointer_address:04x} count={e.queue_count}"
                        stream.write(f"  {label('FIFO Probe:')}{val}\n")

        lat = result.latency_fingerprint
        if lat is not None:
            if lat.error and not lat.responsive:
                stream.write(f"  {label('Latency:')}ERROR - {lat.error}\n")
            elif lat.responsive:
                consistent = "echo consistent" if lat.echo_consistent else "echo inconsistent"
                jitter_str = f"  jitter={lat.jitter_ms:.2f} ms" if lat.jitter_ms is not None else ""
                stream.write(
                    f"  {label('Latency:')}min={lat.min_ms:.1f} ms  avg={lat.avg_ms:.1f} ms"
                    f"  max={lat.max_ms:.1f} ms{jitter_str}  {consistent}\n"
                )

        tls = result.tls_variant
        if tls is not None:
            if not tls.tls_port_open:
                stream.write(f"  {label('Modbus/TLS:')}port {tls.port} closed\n")
            elif not tls.tls_handshake_ok:
                stream.write(f"  {label('Modbus/TLS:')}port open, TLS handshake failed"
                             f"{' - ' + tls.error if tls.error else ''}\n")
            else:
                tls_parts = [f"port {tls.port} open", tls.tls_version or ""]
                if tls.tls_cipher:
                    tls_parts.append(tls.tls_cipher)
                if tls.tls_cert_cn:
                    tls_parts.append(f"CN={tls.tls_cert_cn}")
                responsive_str = (
                    "Modbus responsive" if tls.modbus_over_tls_responsive
                    else "Modbus not responsive"
                )
                tls_parts.append(responsive_str)
                stream.write(f"  {label('Modbus/TLS:')}{' | '.join(p for p in tls_parts if p)}\n")

    stream.write("\n")
    stream.flush()


def export_multi(results: List[ScanResult], outputs: dict, template_meta: Optional[dict] = None) -> None:
    writers = {
        "normal": export_txt,
        "json": lambda res, stream: export_template(res, stream, template_meta),
        "csv": export_csv,
    }

    requested = {key: path for key, path in outputs.items() if path}

    if not requested:
        export_txt(results, sys.stdout)
        return

    for key, path in requested.items():
        writer_func = writers[key]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer_func(results, f)