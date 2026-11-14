from __future__ import annotations

from core.models import ADComputer, ADUser, Finding
from engine.base import Correlator
from utils.constants import UAC_FLAGS


class DelegationCheckCorrelator(Correlator):
    name = "delegation_check"
    requires = ("users", "computers")

    def run(self, results: dict[str, list]) -> list[Finding]:
        users: list[ADUser] = results.get("users", [])
        computers: list[ADComputer] = results.get("computers", [])
        findings: list[Finding] = []

        for user in users:
            if user.uac & UAC_FLAGS["TRUSTED_FOR_DELEGATION"]:
                findings.append(
                    Finding(
                        rule="unconstrained_delegation",
                        severity="critical",
                        principal=user.sam_account_name,
                        target=None,
                        detail={"type": "user"},
                    )
                )

            if user.allowed_to_delegate_to:
                findings.append(
                    Finding(
                        rule="constrained_delegation",
                        severity="high",
                        principal=user.sam_account_name,
                        target=None,
                        detail={
                            "type": "user",
                            "protocol_transition": bool(user.uac & UAC_FLAGS["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
                            "allowed_to_delegate_to": user.allowed_to_delegate_to,
                        },
                    )
                )

            if user.rbcd_configured:
                findings.append(
                    Finding(
                        rule="resource_based_constrained_delegation",
                        severity="high",
                        principal=user.sam_account_name,
                        target=None,
                        detail={"type": "user"},
                    )
                )

        for computer in computers:
            if computer.trusted_for_delegation:
                findings.append(
                    Finding(
                        rule="unconstrained_delegation",
                        severity="critical",
                        principal=computer.sam_account_name,
                        target=None,
                        detail={"type": "computer"},
                    )
                )

            if computer.allowed_to_delegate_to:
                findings.append(
                    Finding(
                        rule="constrained_delegation",
                        severity="high",
                        principal=computer.sam_account_name,
                        target=None,
                        detail={
                            "type": "computer",
                            "protocol_transition": bool(computer.uac & UAC_FLAGS["TRUSTED_TO_AUTH_FOR_DELEGATION"]),
                            "allowed_to_delegate_to": computer.allowed_to_delegate_to,
                        },
                    )
                )

            if computer.rbcd_configured:
                findings.append(
                    Finding(
                        rule="resource_based_constrained_delegation",
                        severity="high",
                        principal=computer.sam_account_name,
                        target=None,
                        detail={"type": "computer"},
                    )
                )

        return findings