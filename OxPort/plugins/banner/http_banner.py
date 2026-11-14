import socket

from plugins.banner.base import BannerResult, failed, no, ok

SERVICE = "http"
PROTOCOL = "tcp"

_REQUEST = b"HEAD / HTTP/1.0\r\nHost: oxport\r\n\r\n"
_MAX_RESPONSE_BYTES = 4096


def _extract_server_header(response: str) -> str:
    for line in response.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return ""


def check(host: str, port: int, timeout_ms: int = 3000) -> BannerResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        sock.sendall(_REQUEST)

        chunks = []
        while True:
            try:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
                if len(b"".join(chunks)) >= _MAX_RESPONSE_BYTES:
                    break
            except socket.timeout:
                break

        raw = b"".join(chunks).decode(errors="replace")

        if not raw:
            return no(SERVICE, host, port, PROTOCOL, "connected but server returned no response")

        status_line = raw.splitlines()[0].strip() if raw.splitlines() else ""
        server_header = _extract_server_header(raw)

        if server_header:
            detail = f"{status_line} | Server: {server_header}"
            return ok(SERVICE, host, port, PROTOCOL, server_header, detail)

        if status_line:
            return ok(SERVICE, host, port, PROTOCOL, status_line, status_line)

        return no(SERVICE, host, port, PROTOCOL, "response contained no usable banner information")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
