from __future__ import annotations

import ipaddress
from typing import Any, Optional

from core.exceptions import ScopeError
from core.utils import as_list, is_ip, normalize_host

VALID_MODES = ("target_only", "strict")


def _domain_match(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _networks(values: list[str], label: str) -> list:
    nets = []
    for value in values:
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ScopeError(f"invalid {label} CIDR '{value}': {exc}") from exc
    return nets


class Scope:
    def __init__(self, data: Optional[dict] = None, primary: Optional[str] = None) -> None:
        data = data or {}
        self.mode = str(data.get("mode") or "target_only").lower()
        if self.mode not in VALID_MODES:
            raise ScopeError(f"unknown scope mode '{self.mode}', expected one of {', '.join(VALID_MODES)}")
        include = data.get("include") or {}
        exclude = data.get("exclude") or {}
        self.include_domains = [normalize_host(d) for d in as_list(include.get("domains"))]
        self.exclude_domains = [normalize_host(d) for d in as_list(exclude.get("domains"))]
        self.include_cidrs = _networks(as_list(include.get("cidrs")), "include")
        self.exclude_cidrs = _networks(as_list(exclude.get("cidrs")), "exclude")
        self.allow_active = bool(data.get("allow_active", True))
        self.primary = primary
        self._raw = data

    def for_target(self, host: str) -> "Scope":
        return Scope(self._raw, primary=normalize_host(host))

    def ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in net for net in self.exclude_cidrs):
            return False
        if self.include_cidrs:
            return any(addr in net for net in self.include_cidrs)
        if self.mode == "strict" and self.primary == ip:
            return True
        return self.mode != "strict" or not self.include_domains

    def host_in_scope(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        if is_ip(host):
            return self.ip_in_scope(host)
        if _domain_match(host, self.exclude_domains):
            return False
        if _domain_match(host, self.include_domains):
            return True
        if self.mode == "target_only" and self.primary and not is_ip(self.primary):
            return _domain_match(host, [self.primary])
        return False

    def validate_target(self, host: str) -> None:
        host = normalize_host(host)
        if is_ip(host):
            if not self.ip_in_scope(host) and not (self.mode == "target_only" and not self.include_cidrs):
                raise ScopeError(f"target {host} is outside the configured scope")
            if any(ipaddress.ip_address(host) in net for net in self.exclude_cidrs):
                raise ScopeError(f"target {host} is excluded by scope")
            return
        if _domain_match(host, self.exclude_domains):
            raise ScopeError(f"target {host} is excluded by scope")
        if self.mode == "strict" and not _domain_match(host, self.include_domains):
            raise ScopeError(f"target {host} is not listed in scope.include.domains (strict mode)")

    def require(self, host: str, action: str = "access") -> None:
        if not self.host_in_scope(host):
            raise ScopeError(f"{action} blocked: {host} is out of scope")

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "include_domains": self.include_domains,
            "exclude_domains": self.exclude_domains,
            "include_cidrs": [str(n) for n in self.include_cidrs],
            "exclude_cidrs": [str(n) for n in self.exclude_cidrs],
            "allow_active": self.allow_active,
        }
