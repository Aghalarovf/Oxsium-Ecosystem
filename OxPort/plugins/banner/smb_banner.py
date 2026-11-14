import socket
import struct

from plugins.banner.base import BannerResult, failed, no, ok

SERVICE = "smb"
PROTOCOL = "tcp"

_SMB2_MAGIC = b"\xfeSMB"
_SMB1_MAGIC = b"\xffSMB"

_SMB2_NEGOTIATE = struct.pack(
    "<4sHHHHIHHQQ16sI",
    _SMB2_MAGIC, 64, 0, 0, 0, 1, 0, 0, 1, 0, b"\x00" * 16, 0,
)
_SMB2_NEGOTIATE_BODY = struct.pack("<HHH", 36, 1, 0x0300)
_SMB2_NEGOTIATE_DIALECTS = struct.pack("<HHH", 0x0202, 0x0210, 0x0300)

_SMB1_NEGOTIATE = (
    b"\xff\x53\x4d\x42"
    b"\x72"
    b"\x00\x00\x00\x00"
    b"\x18"
    b"\x53\xc8"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x01\x00"
    b"\x00\x0c"
    b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
)


def _nbss(payload: bytes) -> bytes:
    return bytes([0x00]) + len(payload).to_bytes(3, "big") + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _recv_nbss(sock: socket.socket) -> bytes:
    hdr = _recv_exact(sock, 4)
    length = int.from_bytes(hdr[1:4], "big")
    return _recv_exact(sock, length)


def _try_smb1(sock: socket.socket) -> str:
    sock.sendall(_nbss(_SMB1_NEGOTIATE))
    reply = _recv_nbss(sock)

    if len(reply) < 4:
        raise ValueError("short SMB1 response")
    if reply[:4] == _SMB2_MAGIC:
        return "SMB2 (server upgraded from SMB1 negotiate)"
    if reply[:4] != _SMB1_MAGIC:
        raise ValueError("not a valid SMB negotiate response")

    return "SMB1 NT LM 0.12"


def check(host: str, port: int, timeout_ms: int = 3000) -> BannerResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))

        try:
            banner = _try_smb1(sock)
            return ok(SERVICE, host, port, PROTOCOL, banner)
        except (ValueError, ConnectionError, struct.error):
            pass

        return no(SERVICE, host, port, PROTOCOL, "connected but could not determine SMB dialect")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()