"""Checks domain_users / domain_computers / domain_groups against the objects
created by tools/New-OxADTestLab.ps1 (admin-rule section).

    python tests/verify_admin_rules.py [output_dir]

Exit code 0 when every expected object matches, 1 otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CATEGORY = {1: "absolute_admin", 2: "absolute_admin", 3: "nested_admin", 4: "nested_admin",
            5: "potential_admin", 6: "potential_admin", 7: "potential_admin"}

# file -> (name key, {object name: expected rule number or None})
EXPECTED = {
    "domain_users.jsonl": ("username", {
        "oxad.r1.da": 1, "oxad.r2.dcsync": 2, "oxad.r3.nested": 3, "oxad.r4.viagroup": 4,
        "oxad.r5.accops": 5, "oxad.r5.nested": 5,
        "oxad.r6.domdacl": 6, "oxad.r6.adminsdh": 6, "oxad.r6.viagroup": 6,
        "oxad.r7.admincount": 7,
        "oxad.pre.da.dcsync": 1, "oxad.pre.nest.cnt": 3,
        "oxad.neg.halfdcsync": None, "oxad.neg.readonly": None,
        "oxad.neg.ouwrite": None, "oxad.neg.nested": None,
    }),
    "domain_groups.jsonl": ("group_name", {
        "OxAD-R1-InDA": 1, "OxAD-R3-Outer": 1, "OxAD-R3-Inner": 3, "OxAD-R4-DCSync": 2,
        "OxAD-R5-Ops": 5, "OxAD-R6-Write": 6,
        "OxAD-R2-DCSync": 2, "OxAD-R4-ViaGrp": 4, "OxAD-R5-Direct": 5, "OxAD-R5-Nested": 5,
        "OxAD-R6-ViaGrp": 6, "OxAD-R6-AdmSDH": 6, "OxAD-R7-AdminCnt": 7,
        "OxAD-Pre-DA-DCSync": 1, "OxAD-Pre-Nest-Cnt": 3,
        "OxAD-Neg-Outer": None, "OxAD-Neg-Inner": None,
        "OxAD-Neg-Half": None, "OxAD-Neg-Read": None, "OxAD-Neg-OUWrite": None,
    }),
    "domain_computers.jsonl": ("computer_name", {
        "OXAD-R1-DA": 1, "OXAD-R2-DCSYNC": 2, "OXAD-R3-NESTED": 3,
        "OXAD-R5-OPS": 5, "OXAD-R6-DACL": 6,
        "OXAD-R4-VIAGRP": 4, "OXAD-R5-NESTED": 5, "OXAD-R6-VIAGRP": 6, "OXAD-PRE-DADCS": 1,
        "OXAD-NEG": None, "OXAD-NEG-HALF": None, "OXAD-NEG-NEST": None,
    }),
}


# OUs / GPOs are not principals: expected (tier0_reason, control_reason), None = no.
OBJECT_EXPECTED = {
    "domain_ous.jsonl": {
        "Domain Controllers": (1, None),
        "Users": (2, 1),            # holds admin-rule test users; oxad.neg.ouwrite has WriteDACL here
        "OU-T0-Admins": (2, None),
        "OU-T0-Full": (2, 1),
        "OU-T0-GW": (2, 2),
        "OU-Plain-Full": (None, 3),
        "OU-Plain-GW": (None, 4),
        "OU-Clean": (None, None),
    },
    "domain_gpos.jsonl": {
        "Default Domain Policy": (1, None),
        "Default Domain Controllers Policy": (2, None),
        "OxAD-GPO-T0-Full": (3, 1),
        "OxAD-GPO-T0-GW": (3, 2),
        "OxAD-GPO-Plain-Full": (None, 3),
        "OxAD-GPO-Plain-GW": (None, 4),
        "OxAD-GPO-Clean": (None, None),
    },
}


def load(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()][1:]


def main(output_dir: str = "output") -> int:
    failures = 0
    for filename, (key, expected) in EXPECTED.items():
        path = Path(output_dir) / filename
        if not path.exists():
            print(f"[MISSING] {path}")
            failures += len(expected)
            continue
        rows = {str(r.get(key)).lower(): r for r in load(path)}
        print(f"\n{filename}")
        for name, rule in expected.items():
            row = rows.get(name.lower())
            if row is None:
                print(f"  FAIL  {name:24} not found in output")
                failures += 1
                continue
            got = row.get("admin_reason")
            flags = [c for c in ("absolute_admin", "nested_admin", "potential_admin") if row.get(c)]
            want_flags = [CATEGORY[rule]] if rule else []
            ok = got == rule and flags == want_flags
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {name:24} rule={got!s:4} flags={flags}"
                  + ("" if ok else f"   expected rule={rule} flags={want_flags}")
                  + (f"   [{row.get('admin_evidence')}]" if row.get("admin_evidence") else ""))
    for filename, expected in OBJECT_EXPECTED.items():
        path = Path(output_dir) / filename
        if not path.exists():
            print(f"[MISSING] {path}")
            failures += len(expected)
            continue
        rows = {str(r.get("name")).lower(): r for r in load(path)}
        print(f"\n{filename}")
        for name, (tier0, control) in expected.items():
            row = rows.get(name.lower())
            if row is None:
                print(f"  FAIL  {name:36} not found in output")
                failures += 1
                continue
            got = (row.get("tier0_reason"), row.get("control_reason"))
            ok = (got == (tier0, control) and row.get("tier0") == (tier0 is not None)
                  and row.get("controlled_by_non_admin") == (control is not None))
            failures += not ok
            who = ", ".join(c["name"] for c in row.get("controllers") or [])
            print(f"  {'PASS' if ok else 'FAIL'}  {name:36} tier0={got[0]!s:4} control={got[1]!s:4}"
                  + ("" if ok else f"   expected tier0={tier0} control={control}")
                  + (f"   [{row.get('tier0_evidence')}]" if row.get("tier0_evidence") else "")
                  + (f"   controllers: {who}" if who else ""))
    print(f"\n{'ALL RULES OK' if not failures else str(failures) + ' MISMATCH(ES)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(*(sys.argv[1:2])))
