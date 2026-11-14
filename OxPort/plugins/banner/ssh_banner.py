import socket

from plugins.banner.base import BannerResult, failed, no, ok

SERVICE = "ssh"
PROTOCOL = "tcp"

_MAX_BANNER_BYTES = 512


def check(host: str, port: int, timeout_ms: int = 3000) -> BannerResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_ms / 1000.0)

    try:
        sock.connect((host, port))
        raw = sock.recv(_MAX_BANNER_BYTES)
        banner = raw.decode(errors="replace").strip()

        if not banner:
            return no(SERVICE, host, port, PROTOCOL, "connected but server sent no banner")

        if not banner.startswith("SSH-"):
            return no(SERVICE, host, port, PROTOCOL, f"unexpected response (not an SSH banner): {banner!r}")

        return ok(SERVICE, host, port, PROTOCOL, banner)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        sock.close()
