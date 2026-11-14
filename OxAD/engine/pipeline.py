"""Engine entry point: raw_*.jsonl + domain_aces.jsonl -> domain_*.jsonl.

    python -m engine --output-dir output            # re-run without LDAP
    engine.pipeline.run(output_dir, ["users"])      # used by oxad.py
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from engine.admin_rules import AdminContext
from engine.base import RawProcessor
from engine.computers_admins import ComputersAdmins
from engine.gpos_admins import GposAdmins
from engine.groups_admins import GroupsAdmins
from engine.object_rules import PRINCIPAL_SOURCES, ObjectContext, PrincipalIndex, domain_dn_from
from engine.ous_admins import OusAdmins
from engine.users_admins import UsersAdmins
from engine.certificates import CertificateProcessor

ACES_FILE = "domain_aces.jsonl"
PROCESSORS: dict[str, type[RawProcessor]] = {
    "users": UsersAdmins,
    "computers": ComputersAdmins,
    "groups": GroupsAdmins,
    "ous": OusAdmins,          # needs the classified users/computers/groups, so it runs after them
    "gpos": GposAdmins,        # same
    "cert": CertificateProcessor,
}
_PRINCIPAL_FILES = {"users": 0, "computers": 1, "groups": 2}   # index into PRINCIPAL_SOURCES

_default_logger = logging.getLogger(__name__)


def read_jsonl(path: Path) -> tuple[dict, list[dict]]:
    """Return (meta_line, records). A missing file gives an empty result."""
    if not path.exists():
        return {}, []
    with open(path, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    return (lines[0], lines[1:]) if lines else ({}, [])


def write_jsonl(path: Path, meta: dict, records: list[dict]) -> None:
    lines = [json.dumps(meta, ensure_ascii=False, default=str)]
    lines.extend(json.dumps(r, ensure_ascii=False, default=str) for r in records)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(output_dir, names: list[str] | None = None, logger: logging.Logger | None = None) -> dict[str, Path]:
    logger = logger or _default_logger
    output_dir = Path(output_dir)
    names = [n for n in PROCESSORS if names is None or n in names]

    _, aces = read_jsonl(output_dir / ACES_FILE)
    if not aces:
        logger.warning("%s missing or empty: ACE based admin rules (2, 4, 6) will not match", ACES_FILE)
    # Group graph is needed for every entity type (nested membership).
    _, groups = read_jsonl(output_dir / "raw_groups.jsonl")
    if not groups:
        logger.warning("raw_groups.jsonl missing or empty: nested admin rules (3, 4, 5) will not match")
    context = AdminContext(groups, aces)
    context.aces = aces

    written: dict[str, Path] = {}
    classified: dict[str, list[dict]] = {}     # principal records classified in this run
    for name in names:
        processor = PROCESSORS[name]()
        raw_path = output_dir / processor.raw_file
        if not raw_path.exists():
            logger.warning("[%s] %s not found, skipped", name, processor.raw_file)
            continue

        meta, records = read_jsonl(raw_path)
        if name in ("ous", "gpos") and context.objects is None:
            context.objects = _object_context(output_dir, classified, aces, records, logger)
        processed = processor.process(records, context)
        if name in _PRINCIPAL_FILES:
            classified[name] = processed

        meta = dict(meta)
        meta["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        meta["meta"] = {
            **(meta.get("meta") or {}),
            "derived_from": [processor.raw_file, ACES_FILE] + ([] if name == "groups" else ["raw_groups.jsonl"]),
        }

        out_path = output_dir / processor.domain_file
        write_jsonl(out_path, meta, processed)
        written[name] = out_path
        logger.info("[%s] engine wrote %d records to %s", name, len(processed), out_path)
    return written


def _object_context(output_dir: Path, classified: dict, aces: list[dict], records: list[dict], logger) -> ObjectContext:
    """Index of classified principals for the OU/GPO rules: records processed
    in this run are used directly, the rest are read from domain_*.jsonl."""
    index = PrincipalIndex()
    for name, i in _PRINCIPAL_FILES.items():
        file_name, name_key, sid_key, dn_key, kind = PRINCIPAL_SOURCES[i]
        if name in classified:
            rows = classified[name]
        else:
            _, rows = read_jsonl(output_dir / file_name)
            if not rows:
                logger.warning("%s missing or empty: OU/GPO tier-0 and control rules will be incomplete", file_name)
        index.add(rows, name_key, sid_key, dn_key, kind)
    domain_dn = domain_dn_from(r.get("dn") or r.get("group_dn") or "" for r in records) or \
        domain_dn_from(a.get("target_dn") for a in aces[:200])
    return ObjectContext(aces, index, domain_dn)
