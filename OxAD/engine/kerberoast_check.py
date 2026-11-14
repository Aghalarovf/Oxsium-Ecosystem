from __future__ import annotations

from core.models import ADUser, Finding
from engine.base import Correlator


class KerberoastCheckCorrelator(Correlator):
    name = "kerberoast_check"
    requires = ("users",)

    def run(self, results: dict[str, list]) -> list[Finding]:
        users: list[ADUser] = results.get("users", [])
        findings: list[Finding] = []

        for user in users:
            if user.spns and user.enabled:
                findings.append(
                    Finding(
                        rule="kerberoastable",
                        severity="high",
                        principal=user.sam_account_name,
                        target=None,
                        detail={"spns": user.spns},
                    )
                )

        return findings
