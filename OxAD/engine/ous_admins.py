from __future__ import annotations

from engine.base import RawProcessor, _insert_fields
from engine.object_rules import OU_TIER0_RULES, ObjectContext


class OusAdmins(RawProcessor):
    """raw_ous.jsonl + domain_aces.jsonl + classified users/computers/groups -> domain_ous.jsonl"""

    name = "ous"
    insert_after = "isaclprotected"

    def process(self, records: list[dict], context) -> list[dict]:
        octx: ObjectContext = context.objects
        principals = octx.principals
        out = []
        for r in records:
            dn = r.get("dn") or ""
            rule, evidence = octx.ou_tier0(dn)
            fields = octx.verdict_fields(dn, rule, OU_TIER0_RULES.get(rule), evidence)

            under = lambda kind: sorted(
                a["name"] for a in octx._under(dn.lower(), principals.admins) if a["type"] == kind)
            users, computers = under("user"), under("computer")
            fields.update({
                "highvalue": rule is not None,
                "privileged_users": users,
                "privileged_users_count": len(users),
                "privileged_computers": computers,
                "privileged_computers_count": len(computers),
                "delegated_permissions": len(fields["controllers"]),
            })
            out.append(_insert_fields(r, fields, self.insert_after))
        return out
