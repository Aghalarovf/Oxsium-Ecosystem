from __future__ import annotations

from engine.base import RawProcessor, _insert_fields
from engine.object_rules import GPO_TIER0_RULES, ObjectContext


class GposAdmins(RawProcessor):
    """raw_gpos.jsonl + domain_aces.jsonl + classified users/computers/groups -> domain_gpos.jsonl"""

    name = "gpos"
    insert_after = "isaclprotected"

    def process(self, records: list[dict], context) -> list[dict]:
        octx: ObjectContext = context.objects
        out = []
        for r in records:
            dn = r.get("dn") or ""
            rule, evidence = octx.gpo_tier0(r.get("linked_containers") or [])
            fields = octx.verdict_fields(dn, rule, GPO_TIER0_RULES.get(rule), evidence)
            fields["highvalue"] = rule is not None
            out.append(_insert_fields(r, fields, self.insert_after))
        return out
