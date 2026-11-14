from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from core.context import ScanContext
from core.modules import Check
from core.utils import load_signature
from modules.whois_dns.records import get_addresses

MODULE = "whois_dns"


def reverse_ip(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(ip.split(".")))
    exploded = addr.exploded.replace(":", "")
    return ".".join(reversed(exploded))


def is_error_response(response: str, error_network: str) -> bool:
    try:
        return ipaddress.ip_address(response) in ipaddress.ip_network(error_network)
    except ValueError:
        return False


class BlacklistCheck(Check):
    module = MODULE
    name = "blacklist"
    description = "DNSBL and URIBL reputation lookups for target IPs and domain"
    passive = True

    def run(self) -> dict[str, Any]:
        signature = load_signature("dns", "dnsbl_zones.json")
        zones = signature["zones"]
        error_network = signature.get("error_network", "127.255.255.0/24")
        domain = None if self.ctx.target.is_ip else self.ctx.target.registered_domain
        max_ips = int(self.option("max_ips", 8))
        ips = [self.ctx.target.host] if self.ctx.target.is_ip else get_addresses(self.ctx)[:max_ips]
        custom_ns = [str(n) for n in self.option("nameservers", [])]
        servers = custom_ns or None

        tasks = self._build_tasks(zones, ips, domain)
        workers = max(1, int(self.option("workers", 20)))
        timeout = float(self.option("timeout", 15))

        def query(task: tuple[str, str, str, str]) -> Optional[dict[str, Any]]:
            zone, label, query_name, query_type = task
            answer = self.ctx.dns.resolve(f"{query_name}.{zone}", "A", servers=servers, use_cache=False)
            if not answer.ok or not answer.records:
                return None
            response = answer.records[0]
            if not response.startswith("127.") or is_error_response(response, error_network):
                return None
            return {"list": label, "zone": zone, "query": query_name, "type": query_type, "response": response}

        hits: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(tasks)))) as pool:
            futures = [pool.submit(query, task) for task in tasks]
            for future in futures:
                result = future.result(timeout=timeout)
                if result:
                    hits.append(result)

        checked = sorted({label for _, label, _, _ in tasks})
        score = len(hits)
        risk = "clean" if score == 0 else "low" if score <= 2 else "medium" if score <= 5 else "high"
        if hits:
            severity = "high" if risk in ("medium", "high") else "medium"
            self.add(
                "BLACKLIST-LISTED",
                f"Listed on {score} blacklist(s)",
                severity,
                f"The target is listed on: {', '.join(sorted({h['list'] for h in hits}))}. This can impact email deliverability and reputation-based filtering.",
                {"hits": hits, "risk": risk},
            )
        return {"ips_checked": ips, "checked": checked, "hits": hits, "score": score, "risk": risk}

    def _build_tasks(self, zones: list[dict[str, Any]], ips: list[str], domain: Optional[str]) -> list[tuple[str, str, str, str]]:
        tasks: list[tuple[str, str, str, str]] = []
        for zone in zones:
            if zone["type"] in ("ip", "both"):
                for ip in ips:
                    try:
                        is_v6 = ipaddress.ip_address(ip).version == 6
                    except ValueError:
                        continue
                    if is_v6 and not zone.get("ipv6"):
                        continue
                    rev = reverse_ip(ip)
                    if rev:
                        tasks.append((zone["zone"], zone["name"], rev, "ip"))
            if zone["type"] in ("domain", "both") and domain:
                tasks.append((zone["zone"], zone["name"], domain, "domain"))
        return tasks