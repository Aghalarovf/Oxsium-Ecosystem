from __future__ import annotations

from functools import lru_cache

from core.utils import load_signature


@lru_cache(maxsize=1)
def _rules() -> list[tuple[str, list[str]]]:
    data = load_signature("dns", "finding_tags.json")
    items = [(str(prefix), list(tags)) for prefix, tags in data["rules"].items()]
    return sorted(items, key=lambda item: len(item[0]), reverse=True)


def tags_for(finding_id: str) -> list[str]:
    for prefix, tags in _rules():
        if finding_id.startswith(prefix):
            return list(tags)
    return []