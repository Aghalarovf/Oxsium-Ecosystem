from __future__ import annotations

from engine.admin_rules import Subject
from engine.base import RawProcessor


class GroupsAdmins(RawProcessor):
    """raw_groups.jsonl + domain_aces.jsonl -> domain_groups.jsonl"""

    name = "groups"
    insert_after = "is_protected"

    def subject(self, record: dict) -> Subject:
        return Subject(
            sid=record.get("group_sid"),
            dn=record.get("group_dn") or "",
            is_group=True,
            admin_count=int(record.get("admin_count") or 0),
            member_of=list(record.get("member_of") or []),
        )
