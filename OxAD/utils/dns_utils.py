from __future__ import annotations

import ipaddress
import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
DNS_PORT = 53
DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 32


def _encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label in {name!r}")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def _build_query(name: str, qtype: int) -> tuple[int, bytes]:
    ident = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return ident, header + _encode_name(name) + struct.pack(">HH", qtype, CLASS_IN)


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def _parse_response(data: bytes, ident: int) -> tuple[bool, int, list[str]]:
    try:
        if len(data) < 12:
            raise ValueError("short DNS response")
        rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        if rid != ident:
            raise ValueError("DNS response id mismatch")
        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(data, offset) + 4
        addresses: list[str] = []
        for _ in range(ancount):
            offset = _skip_name(data, offset)
            rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rtype == TYPE_A and rdlength == 4:
                addresses.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == TYPE_AAAA and rdlength == 16:
                addresses.append(str(ipaddress.IPv6Address(rdata)))
    except (struct.error, IndexError) as exc:
        raise ValueError("malformed DNS response") from exc
    return bool(flags & 0x0200), flags & 0xF, addresses


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = b""
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("DNS TCP connection closed")
        buffer += chunk
    return buffer


def _query_udp(server: str, query: bytes, timeout: float) -> bytes:
    family, _, _, _, address = socket.getaddrinfo(server, DNS_PORT, type=socket.SOCK_DGRAM)[0]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, address)
        return sock.recv(65535)


def _query_tcp(server: str, query: bytes, timeout: float) -> bytes:
    with socket.create_connection((server, DNS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(struct.pack(">H", len(query)) + query)
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, length)


def query_records(server: str, name: str, qtype: int, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    ident, query = _build_query(name, qtype)
    truncated, rcode, addresses = _parse_response(_query_udp(server, query, timeout), ident)
    if truncated:
        truncated, rcode, addresses = _parse_response(_query_tcp(server, query, timeout), ident)
    return addresses if rcode == 0 else []


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _split_families(addresses: list[str]) -> tuple[list[str], list[str]]:
    ipv4: list[str] = []
    ipv6: list[str] = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            continue
        (ipv4 if parsed.version == 4 else ipv6).append(str(parsed))
    return _unique(ipv4), _unique(ipv6)


def _system_resolve(name: str) -> list[str]:
    try:
        return [item[4][0] for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)]
    except (socket.gaierror, UnicodeError, OSError):
        return []


def resolve_host(name: str, server: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[list[str], list[str]]:
    found: list[str] = []
    for qtype in (TYPE_A, TYPE_AAAA):
        try:
            found.extend(query_records(server, name, qtype, timeout))
        except (OSError, ValueError):
            continue
    if not found:
        found = _system_resolve(name)
    return _split_families(found)


def enumerate_ips(
    hosts: dict[str, str],
    server: str,
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
) -> dict[str, tuple[list[str], list[str]]]:
    if not hosts:
        return {}
    keys = list(hosts)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(keys)))) as pool:
        results = pool.map(lambda key: resolve_host(hosts[key], server, timeout), keys)
        return dict(zip(keys, results))