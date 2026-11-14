from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import Finding


class Correlator(ABC):
    name: str = ""
    requires: tuple[str, ...] = ()

    @abstractmethod
    def run(self, results: dict[str, list]) -> list[Finding]:
        raise NotImplementedError


class RawProcessor(ABC):
    """Turns raw_<name>.jsonl (+ domain_aces.jsonl) into domain_<name>.jsonl.

    Subclasses implement `subject()` (how to read a raw record) and
    `extra_fields()` (anything entity specific); the shared admin rules in
    engine/admin_rules.py do the rest.
    """

    name: str = ""                    # users / computers / groups
    insert_after: str | None = None   # key after which the admin fields are placed

    @property
    def raw_file(self) -> str:
        return f"raw_{self.name}.jsonl"

    @property
    def domain_file(self) -> str:
        return f"domain_{self.name}.jsonl"

    def subject(self, record: dict):
        """Principal view of a record (users / computers / groups only)."""
        raise NotImplementedError

    def extra_fields(self, record: dict, verdict) -> dict:
        return {}

    def process(self, records: list[dict], context) -> list[dict]:
        out: list[dict] = []
        for record in records:
            verdict = context.evaluate(self.subject(record))
            fields = {**verdict.as_fields(), **self.extra_fields(record, verdict)}
            out.append(_insert_fields(record, fields, self.insert_after))
        return out


def _insert_fields(record: dict, fields: dict, after: str | None) -> dict:
    """Overwrite keys that already exist in place; put new keys after `after`
    (or at the end when `after` is missing)."""
    merged: dict = {}
    new = {k: v for k, v in fields.items() if k not in record}
    for key, value in record.items():
        merged[key] = fields.get(key, value)
        if key == after:
            merged.update(new)
    if after is None or after not in record:
        merged.update(new)
    return merged
