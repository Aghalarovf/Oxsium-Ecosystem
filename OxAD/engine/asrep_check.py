from __future__ import annotations

from core.models import ADUser, Finding
from engine.base import Correlator
from utils.constants import UAC_FLAGS


class AsrepCheckCorrelator(Correlator):
    name = "asrep_check"
    requires = ("users",)

    def run(self, results: dict[str, list]) -> list[Finding]:
        users: list[ADUser] = results.get("users", [])
        findings: list[Finding] = []

        for user in users:
            if user.enabled and user.uac & UAC_FLAGS["DONT_REQ_PREAUTH"]:
                findings.append(
                    Finding(
                        rule="asrep_roastable",
                        severity="high",
                        principal=user.sam_account_name,
                        target=None,
                        detail={},
                    )
                )

        return findings
