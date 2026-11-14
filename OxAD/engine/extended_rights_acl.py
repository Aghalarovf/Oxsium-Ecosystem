from __future__ import annotations

from core.models import ACE, Finding
from engine.base import Correlator
from engine.risk_loader import load_extended_rights_risk


class ExtendedRightsAclCorrelator(Correlator):
    name = "extended_rights_acl"
    requires = ("aces",)

    def run(self, results: dict[str, list]) -> list[Finding]:
        aces: list[ACE] = results.get("aces", [])
        risk_table = load_extended_rights_risk()
        findings: list[Finding] = []

        for ace in aces:
            if not ace.object_type_guid:
                continue
            severity = risk_table.get(ace.object_type_guid)
            if not severity:
                continue
            findings.append(
                Finding(
                    rule="extended_right",
                    severity=severity,
                    principal=ace.trustee_sid,
                    target=ace.object_dn,
                    detail={"guid": ace.object_type_guid},
                )
            )

        return findings
