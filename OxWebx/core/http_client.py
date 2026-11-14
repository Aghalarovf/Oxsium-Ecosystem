from __future__ import annotations

import json
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import urllib3

from core.exceptions import NetworkError
from core.logger import Logger
from core.config import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOCKS_SCHEMES = ("socks4", "socks4a", "socks5", "socks5h")
HTTP_SCHEMES = ("http", "https")


class RateLimiter:
    def __init__(self, delay: float = 0.0, jitter: float = 0.0) -> None:
        self.delay = max(0.0, float(delay or 0.0))
        self.jitter = max(0.0, float(jitter or 0.0))
        self._lock = threading.Lock()
        self._next = 0.0

    @property
    def enabled(self) -> bool:
        return self.delay > 0 or self.jitter > 0

    def wait(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            now = time.monotonic()
            pause = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.delay + random.uniform(0.0, self.jitter)
        if pause > 0:
            time.sleep(pause)


@dataclass
class HttpResponse:
    url: str
    final_url: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None
    redirects: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError:
            return None

    def to_dict(self, include_body: bool = False) -> dict[str, Any]:
        data = {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "headers": self.headers,
            "elapsed": round(self.elapsed, 3),
            "error": self.error,
            "redirects": self.redirects,
        }
        if include_body:
            data["body"] = self.text
        return data


class HttpClient:
    def __init__(self, settings: Settings, logger: Logger, limiter: RateLimiter) -> None:
        net = settings.section("network")
        self.logger = logger
        self.limiter = limiter
        self.timeout = float(net.get("timeout", 15))
        self.retries = max(0, int(net.get("retries", 1)))
        self.verify = bool(net.get("verify_tls", False))
        self.max_body = int(net.get("max_body_bytes", 1048576))
        self.proxy = net.get("proxy")
        self.user_agent = str(net.get("user_agent") or "oxwebx")
        self.user_agents = [str(u) for u in (net.get("user_agents") or [])]
        self.extra_headers = {str(k): str(v) for k, v in (net.get("headers") or {}).items()}
        self._local = threading.local()
        self._scheme = ""
        if self.proxy:
            parsed = urlparse(self.proxy)
            self._scheme = (parsed.scheme or "").lower()
            if self._scheme not in SOCKS_SCHEMES + HTTP_SCHEMES:
                raise NetworkError(f"unsupported proxy scheme '{self._scheme}'")
            if self._scheme in SOCKS_SCHEMES:
                try:
                    import socks  # noqa: F401
                except ImportError as exc:
                    raise NetworkError("SOCKS proxy requires PySocks: pip install PySocks") from exc

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.verify = self.verify
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}
            self._local.session = session
        return session

    def _headers(self, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
        agent = random.choice(self.user_agents) if self.user_agents else self.user_agent
        headers = {"User-Agent": agent, "Accept": "*/*"}
        headers.update(self.extra_headers)
        if extra:
            headers.update(extra)
        return headers

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
        max_body: Optional[int] = None,
    ) -> HttpResponse:
        method = method.upper()
        limit = self.max_body if max_body is None else max_body
        last_error: Optional[str] = None
        for attempt in range(self.retries + 1):
            self.limiter.wait()
            started = time.monotonic()
            try:
                self.logger.debug(f"HTTP {method} {url}")
                resp = self._session().request(
                    method,
                    url,
                    headers=self._headers(headers),
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                    stream=True,
                )
                try:
                    body = b""
                    if method != "HEAD":
                        for chunk in resp.iter_content(8192):
                            body += chunk
                            if len(body) >= limit:
                                break
                    encoding = resp.encoding or "utf-8"
                    text = body[:limit].decode(encoding, errors="replace")
                    return HttpResponse(
                        url=url,
                        final_url=str(resp.url),
                        status=resp.status_code,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        text=text,
                        elapsed=time.monotonic() - started,
                        redirects=[str(r.url) for r in resp.history],
                    )
                finally:
                    resp.close()
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                self.logger.debug(f"HTTP error {url}: {last_error}")
                if attempt < self.retries:
                    time.sleep(min(2.0, 0.5 * (attempt + 1)))
        return HttpResponse(url=url, final_url=url, error=last_error)

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)

    def get_json(self, url: str, headers: Optional[dict[str, str]] = None) -> Optional[Any]:
        hdrs = {"Accept": "application/json, application/rdap+json, */*"}
        if headers:
            hdrs.update(headers)
        resp = self.get(url, headers=hdrs)
        if resp.status != 200:
            return None
        return resp.json()

    def get_text(self, url: str, headers: Optional[dict[str, str]] = None) -> str:
        resp = self.get(url, headers=headers)
        return resp.text if resp.status == 200 else ""

    def probe_headers(self, url: str) -> HttpResponse:
        head = self.head(url)
        if head.status and head.status < 400:
            return head
        fallback = self.get(url, max_body=65536)
        if fallback.status:
            return fallback
        return head

    def _open_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        if not self.proxy:
            return socket.create_connection((host, port), timeout=timeout)
        parsed = urlparse(self.proxy)
        if self._scheme in SOCKS_SCHEMES:
            import socks

            kind = socks.SOCKS5 if "5" in self._scheme else socks.SOCKS4
            sock = socks.socksocket()
            sock.set_proxy(
                kind,
                parsed.hostname,
                parsed.port or 1080,
                rdns=self._scheme.endswith("h") or self._scheme.endswith("a"),
                username=parsed.username,
                password=parsed.password,
            )
            sock.settimeout(timeout)
            sock.connect((host, port))
            return sock
        sock = socket.create_connection((parsed.hostname, parsed.port or (443 if self._scheme == "https" else 8080)), timeout=timeout)
        sock.settimeout(timeout)
        request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        sock.sendall(request.encode("ascii"))
        buffer = b""
        while b"\r\n\r\n" not in buffer and len(buffer) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buffer += chunk
        status_line = buffer.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        if " 200" not in status_line:
            sock.close()
            raise NetworkError(f"proxy refused CONNECT: {status_line}")
        return sock

    def tcp_query(self, server: str, query: str, port: int = 43, timeout: Optional[float] = None) -> str:
        wait = timeout or self.timeout
        self.limiter.wait()
        sock: Optional[socket.socket] = None
        try:
            sock = self._open_socket(server, port, wait)
            sock.sendall((query + "\r\n").encode("utf-8", errors="replace"))
            chunks: list[bytes] = []
            total = 0
            while total < self.max_body:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except (OSError, NetworkError) as exc:
            self.logger.debug(f"TCP query {server}:{port} failed: {exc}")
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def tcp_probe(self, host: str, port: int, timeout: Optional[float] = None) -> bool:
        self.limiter.wait()
        try:
            sock = self._open_socket(host, port, timeout or min(self.timeout, 5.0))
        except (OSError, NetworkError):
            return False
        try:
            sock.close()
        except OSError:
            pass
        return True
