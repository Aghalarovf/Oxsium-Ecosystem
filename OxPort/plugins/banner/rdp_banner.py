import socket
import struct

from plugins.banner.base import BannerResult, failed, no, ok

SERVICE = "rdp"
PROTOCOL = "tcp"

_X224_CR = (
    b"\x03\x00"
    b"\x00\x13"
    b"\x0e"
    b"\xe0"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00"
    b"Cookie: mstshash=oxport\r\n"
)

_TPKT_X224_CR = (
    b"\x03\x00\x00\x13"
    b"\x0e\xe0\x00\x00\x00\x00\x00"
    b"Cookie: mstshash=oxport\r\n"
)

_NEG_REQ = (
    b"\x03\x00\x00\x13"
    b"\x0e\xe0\x00\x00\x00\x00\x00"
    b"\x01\x00\x08\x00"
    b"\x03\x00\x00\x00"
)

_SECURITY_PROTOCOLS = {
    0x00000001: "SSL/TLS",
    0x00000002: "CredSSP (NLA)",
    0x00000004: "RDSTLS",
    0x00000008: "CredSSP Early User Auth",
}


def _parse_neg_response(data: bytes):
    if len(data) < 11:
        return None, None
    msg_type = data[7]
    if msg_type == 0x02:
        flags = data[8]
        selected = struct.unpack_from("<I", data, 11)[0] if len(data) >= 15 else 0
        return "NEG_RSP", (flags, selected)
    if msg_type == 0x03:
        code = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else 0
        return "NEG_FAIL", code
    return None, None


def check(host: str, port: int, timeout_ms: int = 3000) -> BannerResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        sock.sendall(_NEG_REQ)

        raw = sock.recv(512)
        if not raw:
            return no(SERVICE, host, port, PROTOCOL, "connected but server sent no response to X.224 Connection Request")

        if len(raw) < 4 or raw[0:2] != b"\x03\x00":
            return no(SERVICE, host, port, PROTOCOL, f"unexpected response (not TPKT): {raw[:32].hex()}")

        msg_kind, payload = _parse_neg_response(raw)

        if msg_kind == "NEG_RSP":
            flags, selected = payload
            proto_name = _SECURITY_PROTOCOLS.get(selected, f"0x{selected:08X}")
            nla = bool(selected & 0x00000002)
            banner = f"RDP NegotiationResponse: selected_protocol={proto_name}, NLA={'required' if nla else 'not required'}"
            return ok(SERVICE, host, port, PROTOCOL, banner)

        if msg_kind == "NEG_FAIL":
            return no(SERVICE, host, port, PROTOCOL, f"RDP NegotiationFailure: error_code=0x{payload:08X}")

        return ok(SERVICE, host, port, PROTOCOL, f"RDP (raw: {raw[:32].hex()})")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
