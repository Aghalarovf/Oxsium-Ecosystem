from __future__ import annotations

from engine.admin_rules import Subject
from engine.base import RawProcessor


class UsersAdmins(RawProcessor):
    """raw_users.jsonl + domain_aces.jsonl -> domain_users.jsonl

    Adds absolute_admin / potential_admin / nested_admin / admin_reason /
    admin_description (rules: engine/admin_rules.py). The two checks the old
    admins_check.py performed are kept as rule 7 (adminCount) and rule 2
    (DCSync).
    """

    name = "users"
    insert_after = "preauth_required"

    def subject(self, record: dict) -> Subject:
        return Subject(
            sid=record.get("sid"),
            dn=record.get("dn") or "",
            admin_count=int(record.get("admin_count") or 0),
            primary_group_id=record.get("primary_group_id"),
            member_of=list(record.get("member_of") or []),
        )

    def extra_fields(self, record: dict, verdict) -> dict:
        # `dcsync` was always False in the raw record; now derived from the ACEs.
        return {"dcsync": verdict.dcsync}
