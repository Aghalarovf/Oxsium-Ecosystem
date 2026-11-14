from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

from core.config import Settings
from core.http_client import RateLimiter
from core.logger import Logger

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

OK = "ok"
NODATA = "nodata"
NXDOMAIN = "nxdomain"
TIMEOUT = "timeout"
SERVFAIL = "servfail"
ERROR = "error"


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    status: str
    records: list[str] = field(default_factory=list)
    ttl: Optional[int] = None
    rdata: list[Any] = field(default_factory=list, repr=False)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.rtype,
            "status": self.status,
            "ttl": self.ttl,
            "records": self.records,
            "error": self.error,
        }


class DnsClient:
    def __init__(self, settings: Settings, logger: Logger, limiter: RateLimiter) -> None:
        cfg = settings.section("dns")
        self.logger = logger
        self.limiter = limiter
        self.nameservers = [str(n) for n in (cfg.get("nameservers") or DEFAULT_NAMESERVERS)]
        self.port = int(cfg.get("port", 53))
        self.timeout = float(cfg.get("timeout", 5))
        self.lifetime = float(cfg.get("lifetime", 10))
        self.use_tcp = bool(cfg.get("use_tcp", False))
        self._cache: dict[tuple, DnsAnswer] = {}
        self._zones: dict[str, Optional[str]] = {}
        self._lock = threading.Lock()
        self._local = threading.local()

    def _resolver(self, servers: Optional[list[str]] = None) -> dns.resolver.Resolver:
        store = getattr(self._local, "resolvers", None)
        if store is None:
            store = {}
            self._local.resolvers = store
        key = tuple(servers) if servers else ()
        resolver = store.get(key)
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = list(servers or self.nameservers)
            resolver.port = self.port
            resolver.timeout = self.timeout
            resolver.lifetime = self.lifetime
            resolver.use_edns(0, 0, 1232)
            store[key] = resolver
        return resolver

    def resolve(
        self,
        name: str,
        rtype: str,
        servers: Optional[list[str]] = None,
        use_cache: bool = True,
    ) -> DnsAnswer:
        name = name.rstrip(".").lower()
        rtype = rtype.upper()
        key = (name, rtype, tuple(servers or ()))
        if use_cache:
            with self._lock:
                cached = self._cache.get(key)
            if cached is not None:
                return cached
        self.limiter.wait()
        answer = self._query(name, rtype, servers)
        if use_cache and answer.status != TIMEOUT:
            with self._lock:
                self._cache[key] = answer
        return answer

    def _query(self, name: str, rtype: str, servers: Optional[list[str]]) -> DnsAnswer:
        try:
            result = self._resolver(servers).resolve(name, rtype, tcp=self.use_tcp, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rtype, NXDOMAIN)
        except dns.resolver.NoAnswer:
            return DnsAnswer(name, rtype, NODATA)
        except dns.resolver.NoNameservers as exc:
            return DnsAnswer(name, rtype, SERVFAIL, error=str(exc)[:200])
        except dns.exception.Timeout:
            return DnsAnswer(name, rtype, TIMEOUT, error="timeout")
        except dns.exception.DNSException as exc:
            return DnsAnswer(name, rtype, ERROR, error=f"{type(exc).__name__}: {exc}"[:200])
        except OSError as exc:
            return DnsAnswer(name, rtype, ERROR, error=f"{type(exc).__name__}: {exc}"[:200])
        rdata = list(result)
        return DnsAnswer(
            name=name,
            rtype=rtype,
            status=OK,
            records=[r.to_text() for r in rdata],
            ttl=result.rrset.ttl if result.rrset is not None else None,
            rdata=rdata,
        )

    def raw_query(
        self,
        name: str,
        rtype: str,
        server: str,
        dnssec: bool = False,
        rd: bool = True,
        cd: bool = False,
        tcp: bool = False,
        timeout: Optional[float] = None,
        port: Optional[int] = None,
    ) -> Optional[dns.message.Message]:
        self.limiter.wait()
        try:
            if dnssec:
                message = dns.message.make_query(name, rtype, want_dnssec=True, use_edns=0, payload=4096)
            else:
                message = dns.message.make_query(name, rtype, use_edns=0, payload=1232)
            if not rd:
                message.flags &= ~dns.flags.RD
            if cd:
                message.flags |= dns.flags.CD
            wait = timeout or self.timeout
            where_port = port or self.port
            if tcp:
                return dns.query.tcp(message, server, timeout=wait, port=where_port)
            response, _ = dns.query.udp_with_fallback(message, server, timeout=wait, port=where_port)
            return response
        except (dns.exception.DNSException, OSError) as exc:
            self.logger.debug(f"raw query {name} {rtype} @{server} failed: {exc}")
            return None

    def resolve_ips(self, host: str) -> list[str]:
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            answer = self.resolve(host, rtype)
            for record in answer.records:
                if record not in ips:
                    ips.append(record)
        return ips

    def cname_chain(self, name: str, limit: int = 8) -> list[str]:
        chain: list[str] = []
        current = name
        for _ in range(limit):
            answer = self.resolve(current, "CNAME")
            if not answer.ok or not answer.records:
                break
            target = answer.records[0].rstrip(".").lower()
            if target in chain or target == name:
                break
            chain.append(target)
            current = target
        return chain

    def find_zone(self, name: str) -> Optional[str]:
        name = name.rstrip(".").lower()
        with self._lock:
            if name in self._zones:
                return self._zones[name]
        labels = name.split(".")
        zone: Optional[str] = None
        for index in range(len(labels) - 1):
            candidate = ".".join(labels[index:])
            if self.resolve(candidate, "NS").ok:
                zone = candidate
                break
        with self._lock:
            self._zones[name] = zone
        return zone

    def authoritative(self, name: str) -> dict[str, Any]:
        zone = self.find_zone(name)
        servers: list[dict[str, Any]] = []
        if zone:
            for record in self.resolve(zone, "NS").records:
                host = record.rstrip(".").lower()
                servers.append({"host": host, "ips": self.resolve_ips(host)})
        return {"zone": zone, "servers": servers}
