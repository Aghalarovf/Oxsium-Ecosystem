from __future__ import annotations

from datetime import datetime, timezone
from time import monotonic
from typing import Any

from core.events import CHECK_FAILED, CHECK_FINISHED, CHECK_STARTED, MODULE_FINISHED, MODULE_STARTED
from core.models import ModuleResult
from core.modules import BaseModule, Check
from modules.whois_dns.blacklist import BlacklistCheck
from modules.whois_dns.dnssec import DnssecCheck
from modules.whois_dns.historical import CrossSearchCheck, HistoricalCheck
from modules.whois_dns.records import EmailSecurityCheck, RecordsCheck, TtlAnomalyCheck
from modules.whois_dns.reverse_dns import CdnCheck, IpIntelCheck, ReverseDnsCheck
from modules.whois_dns.tags import tags_for
from modules.whois_dns.whois import WhoisCheck
from modules.whois_dns.zone_transfer import DanglingCheck, ZoneTransferCheck


CHECKS: dict[str, type[Check]] = {
    cls.name: cls
    for cls in (
        RecordsCheck,
        WhoisCheck,
        EmailSecurityCheck,
        ReverseDnsCheck,
        IpIntelCheck,
        CdnCheck,
        ZoneTransferCheck,
        DnssecCheck,
        TtlAnomalyCheck,
        DanglingCheck,
        BlacklistCheck,
        HistoricalCheck,
        CrossSearchCheck,
    )
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WhoisDnsModule(BaseModule):
    name = "whois_dns"
    description = "WHOIS, RDAP, DNS, DNSSEC, mail security and infrastructure intelligence"
    category = "discovery"
    passive = True
    version = "1.0.0"

    def run(self) -> ModuleResult:
        started = monotonic()
        result = ModuleResult(module=self.name, status="running", started_at=_timestamp())
        configured = self.ctx.option(self.name, "checks", list(CHECKS))
        names = [str(name) for name in configured]
        self.ctx.emit(MODULE_STARTED, module=self.name, checks=names)
        for name in names:
            check_cls = CHECKS.get(name)
            if check_cls is None:
                result.errors.append(f"unknown check '{name}'")
                continue
            check = check_cls(self.ctx)
            check.tag_resolver = tags_for
            if check.domain_only and self.ctx.target.is_ip:
                result.checks.append({"check": name, "status": "skipped", "reason": "domain target required"})
                continue
            if self.ctx.passive_only and not check.passive:
                result.checks.append({"check": name, "status": "skipped", "reason": "passive-only mode"})
                continue
            self.ctx.emit(CHECK_STARTED, module=self.name, check=name)
            check_started = monotonic()
            try:
                data = check.run()
                result.data[name] = data
                result.findings.extend(check.findings)
                result.errors.extend(check.errors)
                result.checks.append({
                    "check": name,
                    "status": "completed",
                    "duration": round(monotonic() - check_started, 3),
                })
                self.ctx.emit(CHECK_FINISHED, module=self.name, check=name, status="completed")
            except Exception as exc:
                message = f"{name}: {type(exc).__name__}: {exc}"
                result.errors.append(message)
                result.checks.append({"check": name, "status": "failed", "error": message})
                self.ctx.emit(CHECK_FAILED, module=self.name, check=name, error=message)
                self.ctx.logger.debug(message)
        result.status = "failed" if result.errors and not result.findings else "completed"
        result.finished_at = _timestamp()
        result.duration = monotonic() - started
        self.ctx.emit(MODULE_FINISHED, module=self.name, status=result.status)
        return result


MODULE = WhoisDnsModule