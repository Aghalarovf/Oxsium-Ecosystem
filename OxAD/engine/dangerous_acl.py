from __future__ import annotations

from core.models import ACE, Finding
from engine.base import Correlator
from engine.risk_loader import load_acl_risk


class DangerousAclCorrelator(Correlator):
    name = "dangerous_acl"
    requires = ("aces",)

    def run(self, results: dict[str, list]) -> list[Finding]:
        aces: list[ACE] = results.get("aces", [])
        risk_table = load_acl_risk()
        findings: list[Finding] = []

        for ace in aces:
            if ace.inherited:
                continue
            for right in ace.rights:
                severity = risk_table.get(right)
                if not severity:
                    continue
                findings.append(
                    Finding(
                        rule="dangerous_acl",
                        severity=severity,
                        principal=ace.trustee_sid,
                        target=ace.object_dn,
                        detail={"right": right, "object_type": ace.object_type},
                    )
                )

        return findings
