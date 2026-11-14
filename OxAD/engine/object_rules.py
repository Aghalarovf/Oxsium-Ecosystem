"""Rules for objects that are NOT principals: OUs and GPOs.

An OU or GPO cannot be an admin, so instead of absolute/nested/potential_admin
two questions are answered:

  tier0       - does compromising this object compromise Tier-0?
                (fields: tier0, tier0_reason, tier0_description, tier0_evidence)
  control     - which non-admin principals can take the object over?
                (fields: controlled_by_non_admin, control_reason,
                 control_description, controllers)

Tier-0 rules, OU:
    1  is the Domain Controllers OU / holds a domain controller computer
    2  holds admin principals (absolute_admin or nested_admin users, computers, groups)
Tier-0 rules, GPO (only enabled links count):
    1  linked to the domain root
    2  linked to the Domain Controllers OU (or an OU that holds a domain controller)
    3  linked to an OU that holds admin principals

Control rules (strongest wins, lowest number):
    1  non-admin has GenericAll/WriteDACL/WriteOwner on a Tier-0 object
    2  non-admin has GenericWrite on a Tier-0 object
    3  non-admin has GenericAll/WriteDACL/WriteOwner on a non-Tier-0 object
    4  non-admin has GenericWrite on a non-Tier-0 object
"admin" = absolute_admin or nested_admin (as classified by users/computers/groups).
Rights held through group membership are not expanded: the group that holds the
ACE is reported as the controller.
"""
from __future__ import annotations

import re

from utils.constants import WELL_KNOWN_SIDS

OU_TIER0_RULES = {
    1: "Is the Domain Controllers OU or holds a domain controller computer",
    2: "Holds admin principals (absolute_admin / nested_admin users, computers or groups)",
}
GPO_TIER0_RULES = {
    1: "Linked (enabled) to the domain root",
    2: "Linked (enabled) to the Domain Controllers OU or an OU holding a domain controller",
    3: "Linked (enabled) to an OU that holds admin principals",
}
CONTROL_RULES = {
    1: "Non-admin principal has GenericAll/WriteDACL/WriteOwner on a Tier-0 object",
    2: "Non-admin principal has GenericWrite on a Tier-0 object",
    3: "Non-admin principal has GenericAll/WriteDACL/WriteOwner on the object",
    4: "Non-admin principal has GenericWrite on the object",
}

FULL_RIGHTS = {"GenericAll", "WriteDACL", "WriteOwner"}
WRITE_RIGHTS = {"GenericWrite"}
ACE_ALLOW_TYPES = {0, 5}
# SYSTEM, Creator Owner, Creator Group, Self, Enterprise Domain Controllers: always present, never a finding.
IGNORED_SIDS = {"S-1-5-18", "S-1-3-0", "S-1-3-1", "S-1-5-10", "S-1-5-9"}

# (file name, name key, sid key, dn key, object type)
PRINCIPAL_SOURCES = (
    ("domain_users.jsonl", "username", "sid", "dn", "user"),
    ("domain_computers.jsonl", "computer_name", "sid", "dn", "computer"),
    ("domain_groups.jsonl", "group_name", "group_sid", "group_dn", "group"),
)


def classify(record: dict) -> str | None:
    for key in ("absolute_admin", "nested_admin", "potential_admin"):
        if record.get(key):
            return key
    return None


class PrincipalIndex:
    """Classified users/computers/groups (output of the principal processors)."""

    def __init__(self):
        self.by_sid: dict[str, dict] = {}
        self.admins: list[dict] = []          # absolute_admin / nested_admin only
        self.domain_controllers: list[str] = []   # dn (lower)

    def add(self, records: list[dict], name_key: str, sid_key: str, dn_key: str, kind: str) -> None:
        for r in records:
            entry = {
                "name": r.get(name_key), "sid": r.get(sid_key), "dn": str(r.get(dn_key) or ""),
                "type": kind, "class": classify(r),
            }
            if entry["sid"]:
                self.by_sid[entry["sid"]] = entry
            if entry["class"] in ("absolute_admin", "nested_admin"):
                self.admins.append(entry)
            if kind == "computer" and r.get("is_domain_controller"):
                self.domain_controllers.append(entry["dn"].lower())

    def is_admin(self, sid: str) -> bool:
        e = self.by_sid.get(sid)
        return bool(e and e["class"] in ("absolute_admin", "nested_admin"))

    def name_of(self, sid: str) -> str:
        e = self.by_sid.get(sid)
        return (e["name"] if e else None) or WELL_KNOWN_SIDS.get(sid) or sid


_DOMAIN_PART_RE = re.compile(r"(?:^|,)(dc=.*)$", re.IGNORECASE)


def domain_dn_from(dns) -> str:
    for dn in dns:
        m = _DOMAIN_PART_RE.search(str(dn or ""))
        if m:
            return m.group(1)
    return ""


class ObjectContext:
    def __init__(self, aces: list[dict], principals: PrincipalIndex, domain_dn: str):
        self.principals = principals
        self.domain_dn = domain_dn.lower()
        self.dc_ou_dn = f"ou=domain controllers,{self.domain_dn}"
        # target dn (lower) -> list of (principal sid, rights)
        self.acl: dict[str, list[tuple[str, set[str]]]] = {}
        interesting = FULL_RIGHTS | WRITE_RIGHTS
        for ace in aces:
            if ace.get("ace_type_raw") not in ACE_ALLOW_TYPES:
                continue
            hit = set(ace.get("rights") or []) & interesting
            if hit and ace.get("principal_sid"):
                self.acl.setdefault(str(ace.get("target_dn") or "").lower(), []).append(
                    (ace["principal_sid"], hit))

    # -- Tier-0 --------------------------------------------------------------

    def _under(self, dn_lower: str, dns) -> list:
        suffix = "," + dn_lower
        return [d for d in dns if d["dn"].lower().endswith(suffix)]

    def ou_tier0(self, dn: str) -> tuple[int | None, str | None]:
        low = dn.lower()
        if low == self.dc_ou_dn:
            return 1, "Domain Controllers OU"
        dcs = [d for d in self.principals.domain_controllers if d.endswith("," + low)]
        if dcs:
            return 1, f"holds domain controller {dcs[0].split(',')[0][3:]}"
        admins = self._under(low, self.principals.admins)
        if admins:
            names = ", ".join(sorted(a["name"] for a in admins)[:5])
            more = f" (+{len(admins) - 5} more)" if len(admins) > 5 else ""
            return 2, f"holds {len(admins)} admin principal(s): {names}{more}"
        return None, None

    def gpo_tier0(self, links: list[dict]) -> tuple[int | None, str | None]:
        best: tuple[int, str] | None = None
        for link in links:
            if link.get("link_enabled") is False:
                continue
            target = str(link.get("dn") or "")
            low = target.lower()
            if low == self.domain_dn:
                cand = (1, f"linked to domain root {target}")
            else:
                rule, why = self.ou_tier0(target)
                if rule == 1:
                    cand = (2, f"linked to {target} ({why})")
                elif rule == 2:
                    cand = (3, f"linked to {target} ({why})")
                else:
                    continue
            if best is None or cand[0] < best[0]:
                best = cand
        return best if best else (None, None)

    # -- control -------------------------------------------------------------

    def controllers(self, dn: str, tier0: bool) -> tuple[int | None, list[dict]]:
        merged: dict[str, set[str]] = {}
        for sid, rights in self.acl.get(dn.lower(), []):
            if sid in IGNORED_SIDS or self.principals.is_admin(sid):
                continue
            merged.setdefault(sid, set()).update(rights)

        result: list[dict] = []
        for sid, rights in sorted(merged.items()):
            full = bool(rights & FULL_RIGHTS)
            rule = (1 if full else 2) if tier0 else (3 if full else 4)
            entry = self.principals.by_sid.get(sid)
            result.append({
                "sid": sid,
                "name": self.principals.name_of(sid),
                "type": entry["type"] if entry else None,
                "principal_class": entry["class"] if entry else None,
                "rights": sorted(rights),
                "rule": rule,
            })
        result.sort(key=lambda c: (c["rule"], c["name"] or ""))
        return (result[0]["rule"] if result else None), result

    # -- shared field builder ------------------------------------------------

    def verdict_fields(self, dn: str, tier0_rule, tier0_desc, tier0_evidence) -> dict:
        control_rule, controllers = self.controllers(dn, tier0_rule is not None)
        return {
            "tier0": tier0_rule is not None,
            "tier0_reason": tier0_rule,
            "tier0_description": tier0_desc,
            "tier0_evidence": tier0_evidence,
            "controlled_by_non_admin": control_rule is not None,
            "control_reason": control_rule,
            "control_description": CONTROL_RULES.get(control_rule),
            "controllers": controllers,
        }
