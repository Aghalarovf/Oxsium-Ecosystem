from __future__ import annotations

from engine.admin_rules import Subject
from engine.base import RawProcessor


class ComputersAdmins(RawProcessor):
    """raw_computers.jsonl + raw_groups.jsonl + domain_aces.jsonl -> domain_computers.jsonl"""

    name = "computers"
    insert_after = "potential_privileged"

    def subject(self, record: dict) -> Subject:
        return Subject(
            sid=record.get("sid"),
            dn=record.get("dn") or "",
            is_dc=bool(record.get("is_domain_controller")),
            primary_group_id=record.get("primary_group_id"),
        )

    def extra_fields(self, record: dict, verdict) -> dict:
        any_admin = verdict.absolute_admin or verdict.nested_admin or verdict.potential_admin
        return {"potential_privileged": any_admin}
