import re
import socket
import ssl

from plugins.http_enum.base import HttpEnumResult, failed, ok

_MAX_BYTES = 65536
_RECV_CHUNK = 4096

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


def _parse_status_line(raw_headers: bytes):
    first_line = raw_headers.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = first_line.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])
        status_text = parts[2] if len(parts) > 2 else ""
        return status_code, status_text
    return None, ""


def _parse_headers(raw_headers: bytes):
    headers = {}
    lines = raw_headers.decode(errors="replace").split("\r\n")
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def _extract_title(body: bytes):
    match = _TITLE_RE.search(body)
    if not match:
        return None
    title = match.group(1).decode(errors="replace")
    title = " ".join(title.split()).strip()
    return title or None


def _extract_technologies(headers, body: bytes):
    technologies = []

    server = headers.get("Server")
    if server:
        technologies.append(server)

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        technologies.append(powered_by)

    generator_match = _GENERATOR_RE.search(body)
    if generator_match:
        technologies.append(generator_match.group(1).decode(errors="replace"))

    set_cookie = headers.get("Set-Cookie", "")
    if "wordpress" in set_cookie.lower():
        technologies.append("WordPress")

    via = headers.get("Via")
    if via:
        technologies.append(f"Via: {via}")

    return technologies


def _read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < _MAX_BYTES:
        chunk = sock.recv(_RECV_CHUNK)
        if not chunk:
            break
        data += chunk

    if b"\r\n\r\n" not in data:
        return data, b""

    header_part, _, body_part = data.partition(b"\r\n\r\n")

    while len(body_part) < _MAX_BYTES:
        try:
            chunk = sock.recv(_RECV_CHUNK)
        except socket.timeout:
            break
        if not chunk:
            break
        body_part += chunk

    return header_part, body_part


def probe(host: str, port: int, scheme: str, timeout_ms: int = 3000) -> HttpEnumResult:
    timeout_s = timeout_ms / 1000.0
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout_s)
    sock = raw_sock

    try:
        raw_sock.connect((host, port))

        if scheme == "https":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw_sock, server_hostname=host)

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: oxport-http-enum\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(request)

        header_part, body_part = _read_response(sock)

        if not header_part:
            return failed(host, port, scheme, "no response received")

        status_code, status_text = _parse_status_line(header_part)
        if status_code is None:
            return failed(host, port, scheme, "response was not a valid HTTP status line")

        headers = _parse_headers(header_part)
        title = _extract_title(body_part)
        technologies = _extract_technologies(headers, body_part)

        return ok(
            host=host,
            port=port,
            scheme=scheme,
            status_code=status_code,
            status_text=status_text,
            title=title,
            server=headers.get("Server"),
            powered_by=headers.get("X-Powered-By"),
            location=headers.get("Location"),
            headers=headers,
            technologies=technologies,
        )
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as exc:
        return failed(host, port, scheme, str(exc))
    finally:
        try:
            sock.close()
        except Exception:
            pass
