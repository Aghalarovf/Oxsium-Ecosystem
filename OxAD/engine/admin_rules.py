"""Shared admin-classification rules used by users_admins / computers_admins /
groups_admins.

Every principal (user, computer or group) is evaluated against the numbered
rules below, in order. The first rule that matches decides the result:

    absolute_admin  - already holds domain-admin level power         (rules 1-2)
    nested_admin    - gets that power through nested group membership (rules 3-4)
    potential_admin - can plausibly become admin / is admin-like      (rules 5-7)

`admin_reason` is the matching rule number and `admin_description` its text.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------

ABSOLUTE = "absolute_admin"
NESTED = "nested_admin"
POTENTIAL = "potential_admin"

RULES: dict[int, dict[str, str]] = {
    1: {
        "category": ABSOLUTE,
        "description": "Direct member of (or is itself) a Tier-0 group "
                       "(Domain Admins, Enterprise Admins, Schema Admins, Administrators, Domain Controllers)",
    },
    2: {
        "category": ABSOLUTE,
        "description": "Holds DCSync rights (DS-Replication-Get-Changes + Get-Changes-All) "
                       "directly on the domain object",
    },
    3: {
        "category": NESTED,
        "description": "Nested (indirect) member of a Tier-0 group through group nesting",
    },
    4: {
        "category": NESTED,
        "description": "Obtains DCSync rights on the domain object through group membership "
                       "or a well-known principal",
    },
    5: {
        "category": POTENTIAL,
        "description": "Member of (or is itself) a privileged operator group "
                       "(Account/Server/Print/Backup Operators, Key Admins, Enterprise Key Admins)",
    },
    6: {
        "category": POTENTIAL,
        "description": "Holds GenericAll/GenericWrite/WriteDACL/WriteOwner/All-Extended-Rights on the domain "
                       "object, AdminSDHolder or a Tier-0 group (own or through group membership)",
    },
    7: {
        "category": POTENTIAL,
        "description": "adminCount > 0 (protected by AdminSDHolder) without matching any stronger rule",
    },
}

# Tier-0 / operator groups. Built-in groups are matched by full SID, domain
# groups by RID (so the check works for any domain SID).
TIER0_BUILTIN_SIDS = {"S-1-5-32-544"}
TIER0_DOMAIN_RIDS = {512, 516, 518, 519}

OPERATOR_BUILTIN_SIDS = {"S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"}
OPERATOR_DOMAIN_RIDS = {526, 527}

# Principals every authenticated account implicitly belongs to.
IMPLICIT_SIDS = ("S-1-1-0", "S-1-5-11")           # Everyone, Authenticated Users
IMPLICIT_DC_SIDS = ("S-1-5-9",)                    # Enterprise Domain Controllers

DCSYNC_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DCSYNC_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

# Rights that give full (or DACL-level) control over the target object.
DANGEROUS_RIGHTS = {"GenericAll", "GenericWrite", "WriteDACL", "WriteOwner", "All-Extended-Rights"}
# Rights that cover every extended right (including both DCSync GUIDs).
ALL_EXTENDED_RIGHTS = {"GenericAll", "All-Extended-Rights"}

ACE_ALLOW_TYPES = {0, 5}  # ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT


# ---------------------------------------------------------------------------
# Input / output
# ---------------------------------------------------------------------------

@dataclass
class Subject:
    """Normalised view of a user / computer / group record."""
    sid: str | None
    dn: str
    is_group: bool = False
    is_dc: bool = False
    admin_count: int = 0
    primary_group_id: int | None = None
    member_of: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    absolute_admin: bool = False
    potential_admin: bool = False
    nested_admin: bool = False
    admin_reason: int | None = None
    admin_description: str | None = None
    admin_evidence: str | None = None
    dcsync: bool = False   # effective DCSync (own + group + implicit principals); not exported by as_fields

    def as_fields(self) -> dict:
        return {
            "absolute_admin": self.absolute_admin,
            "potential_admin": self.potential_admin,
            "nested_admin": self.nested_admin,
            "admin_reason": self.admin_reason,
            "admin_description": self.admin_description,
            "admin_evidence": self.admin_evidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rid(sid: str | None) -> int | None:
    try:
        return int(str(sid).rsplit("-", 1)[-1])
    except (TypeError, ValueError):
        return None


def _is_domain_sid(sid: str | None) -> bool:
    return bool(sid) and str(sid).startswith("S-1-5-21-")


def is_tier0_sid(sid: str | None) -> bool:
    if not sid:
        return False
    return sid in TIER0_BUILTIN_SIDS or (_is_domain_sid(sid) and _rid(sid) in TIER0_DOMAIN_RIDS)


def is_operator_sid(sid: str | None) -> bool:
    if not sid:
        return False
    return sid in OPERATOR_BUILTIN_SIDS or (_is_domain_sid(sid) and _rid(sid) in OPERATOR_DOMAIN_RIDS)


def domain_sid_of(sid: str | None) -> str | None:
    if not _is_domain_sid(sid):
        return None
    return str(sid).rsplit("-", 1)[0]


def _group_name(dn: str) -> str:
    first = str(dn).split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else first


# ---------------------------------------------------------------------------
# Context (group graph + ACE index), built once per engine run
# ---------------------------------------------------------------------------

class AdminContext:
    def __init__(self, groups: list[dict], aces: list[dict], domain_sid: str | None = None):
        self.objects = None   # ObjectContext, built lazily by the pipeline for OU/GPO rules
        self.domain_sid = domain_sid or self._guess_domain_sid(groups, aces)
        self.group_by_dn: dict[str, dict] = {}
        self.group_by_sid: dict[str, dict] = {}
        self.parents: dict[str, set[str]] = {}   # object dn(lower) -> parent group dn(lower)

        for g in groups:
            dn = str(g.get("group_dn") or "").lower()
            if not dn:
                continue
            self.group_by_dn[dn] = g
            if g.get("group_sid"):
                self.group_by_sid[g["group_sid"]] = g

        for g in groups:
            gdn = str(g.get("group_dn") or "").lower()
            for parent in g.get("member_of") or []:
                self.parents.setdefault(gdn, set()).add(str(parent).lower())
            for m in g.get("members") or []:
                mdn = str(m.get("member_dn") or "").lower()
                if mdn:
                    self.parents.setdefault(mdn, set()).add(gdn)

        self._index_aces(aces)

    # -- ACL index ---------------------------------------------------------

    @staticmethod
    def _guess_domain_sid(groups, aces) -> str | None:
        for g in groups:
            ds = domain_sid_of(g.get("group_sid"))
            if ds:
                return ds
        for a in aces:
            ds = domain_sid_of(a.get("target_sid"))
            if ds:
                return ds
        return None

    def _index_aces(self, aces: list[dict]) -> None:
        # principal sid -> set of DCSync GUIDs held on the domain root
        self.dcsync: dict[str, set[str]] = {}
        # principal sid -> descriptions of dangerous rights on sensitive targets
        self.dangerous: dict[str, list[str]] = {}

        for ace in aces:
            if ace.get("ace_type_raw") not in ACE_ALLOW_TYPES:
                continue
            principal = ace.get("principal_sid")
            if not principal:
                continue
            rights = set(ace.get("rights") or [])
            target_sid = ace.get("target_sid") or ""
            target_dn = str(ace.get("target_dn") or "")
            is_domain_root = (
                ace.get("target_type") == "Domain"
                and bool(self.domain_sid)
                and target_sid == self.domain_sid
            )

            if is_domain_root:
                guid = (ace.get("object_acetype") or "").lower()
                if rights & ALL_EXTENDED_RIGHTS and not guid:
                    self.dcsync.setdefault(principal, set()).update(
                        {DCSYNC_GET_CHANGES, DCSYNC_GET_CHANGES_ALL}
                    )
                elif guid in (DCSYNC_GET_CHANGES, DCSYNC_GET_CHANGES_ALL):
                    self.dcsync.setdefault(principal, set()).add(guid)

            hit = rights & DANGEROUS_RIGHTS
            if not hit:
                continue
            if is_domain_root:
                label = "domain object"
            elif target_dn.lower().startswith("cn=adminsdholder,cn=system,"):
                label = "AdminSDHolder"
            elif ace.get("target_type") == "Group" and is_tier0_sid(target_sid):
                label = f"Tier-0 group {ace.get('target_name')}"
            else:
                continue
            self.dangerous.setdefault(principal, []).append(f"{sorted(hit)[0]} on {label}")

    # -- group membership --------------------------------------------------

    def memberships(self, subject: Subject) -> dict[str, list[str]]:
        """All groups the subject belongs to -> path of group names (nearest first).

        A path of length 1 is a direct membership, longer is nested. The
        primary group counts as direct.
        """
        start: dict[str, list[str]] = {}
        own = subject.dn.lower()
        direct = set(self.parents.get(own, set())) | {str(d).lower() for d in subject.member_of}
        if subject.primary_group_id is not None and self.domain_sid:
            pg = self.group_by_sid.get(f"{self.domain_sid}-{subject.primary_group_id}")
            if pg:
                direct.add(str(pg["group_dn"]).lower())

        result: dict[str, list[str]] = {}
        queue: deque[tuple[str, list[str]]] = deque()
        for dn in sorted(direct):
            queue.append((dn, [self._name(dn)]))
        while queue:
            dn, path = queue.popleft()
            if dn in result or dn == own:
                continue
            result[dn] = path
            for parent in sorted(self.parents.get(dn, ())):
                if parent not in result:
                    queue.append((parent, path + [self._name(parent)]))
        return result

    def _name(self, dn_lower: str) -> str:
        g = self.group_by_dn.get(dn_lower)
        return g["group_name"] if g else _group_name(dn_lower)

    def _group_sid(self, dn_lower: str) -> str | None:
        g = self.group_by_dn.get(dn_lower)
        return g.get("group_sid") if g else None

    # -- evaluation ----------------------------------------------------------

    def evaluate(self, subject: Subject) -> Verdict:
        groups = self.memberships(subject)
        group_sids = {dn: self._group_sid(dn) for dn in groups}

        effective = set(IMPLICIT_SIDS)
        if subject.is_dc:
            effective.update(IMPLICIT_DC_SIDS)
        if subject.sid:
            effective.add(subject.sid)
        effective.update(s for s in group_sids.values() if s)

        def tier0_groups(direct: bool) -> list[tuple[str, list[str]]]:
            return [
                (dn, path) for dn, path in groups.items()
                if is_tier0_sid(group_sids[dn]) and (len(path) == 1) == direct
            ]

        def dcsync_held(sids) -> bool:
            held: set[str] = set()
            for sid in sids:
                held |= self.dcsync.get(sid, set())
            return {DCSYNC_GET_CHANGES, DCSYNC_GET_CHANGES_ALL} <= held

        verdict = self._evaluate_rules(subject, groups, group_sids, effective, tier0_groups, dcsync_held)
        verdict.dcsync = dcsync_held(effective)
        return verdict

    def _evaluate_rules(self, subject, groups, group_sids, effective, tier0_groups, dcsync_held) -> Verdict:
        # 1 - direct Tier-0 membership / is Tier-0 group
        if subject.is_group and is_tier0_sid(subject.sid):
            return self._verdict(1, f"is Tier-0 group {_group_name(subject.dn)}")
        direct0 = tier0_groups(direct=True)
        if direct0:
            return self._verdict(1, f"member of {self._name(direct0[0][0])}")

        # 2 - DCSync held by the principal itself
        if subject.sid and dcsync_held([subject.sid]):
            return self._verdict(2, "DCSync ACEs on domain object granted to the principal")

        # 3 - nested Tier-0 membership
        nested0 = tier0_groups(direct=False)
        if nested0:
            dn, path = nested0[0]
            return self._verdict(3, " -> ".join(path))

        # 4 - DCSync through groups / implicit principals
        if dcsync_held(effective):
            via = [self._name(dn) for dn, s in group_sids.items() if s and self.dcsync.get(s)]
            return self._verdict(4, "DCSync via " + ", ".join(sorted(set(via)) or ["well-known principal"]))

        # 5 - operator groups
        if subject.is_group and is_operator_sid(subject.sid):
            return self._verdict(5, f"is operator group {_group_name(subject.dn)}")
        ops = sorted(
            (path for dn, path in groups.items() if is_operator_sid(group_sids[dn])),
            key=len,
        )
        if ops:
            return self._verdict(5, " -> ".join(ops[0]))

        # 6 - dangerous ACEs on domain / AdminSDHolder / Tier-0 groups
        for sid in sorted(effective):
            if self.dangerous.get(sid):
                return self._verdict(6, f"{self.dangerous[sid][0]} (principal {sid})")

        # 7 - adminCount
        if subject.admin_count and subject.admin_count > 0:
            return self._verdict(7, f"adminCount={subject.admin_count}")

        return Verdict()

    @staticmethod
    def _verdict(rule: int, evidence: str) -> Verdict:
        category = RULES[rule]["category"]
        return Verdict(
            absolute_admin=category == ABSOLUTE,
            nested_admin=category == NESTED,
            potential_admin=category == POTENTIAL,
            admin_reason=rule,
            admin_description=RULES[rule]["description"],
            admin_evidence=evidence,
        )
