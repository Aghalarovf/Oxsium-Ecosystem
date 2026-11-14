"""Compare object ACE GUIDs in OxDirectory's domain database with OxAD constants."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Iterable
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
OXAD_ROOT = SCRIPT_DIR.parent
DEFAULT_DATABASE = OXAD_ROOT.parent / "OxDirectory" / "uploads" / "domain.db"
CONSTANTS_DIR = OXAD_ROOT / "modules" / "aces"
sys.path.insert(0, str(CONSTANTS_DIR))

from constants import OBJECT_TYPE_RIGHTS  # noqa: E402


def load_database_guids(database: Path) -> dict[str, int]:
    """Return unique non-empty object ACE GUIDs and their database row counts."""
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            """
            SELECT LOWER(TRIM(object_acetype)) AS guid, COUNT(*) AS row_count
            FROM domain_aces
            WHERE TRIM(COALESCE(object_acetype, '')) <> ''
            GROUP BY LOWER(TRIM(object_acetype))
            ORDER BY guid
            """
        ).fetchall()
    return {guid: row_count for guid, row_count in rows}


def print_section(title: str, guids: Iterable[str], counts: dict[str, int]) -> None:
    entries = list(guids)
    print(f"\n{title}: {len(entries)}")
    if not entries:
        print("  None")
        return
    for guid in entries:
        suffix = f" ({counts[guid]} database rows)" if counts else ""
        print(f"  {guid}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Find object ACE GUIDs present in domain.db but missing from "
            "OxAD/modules/aces/constants.py."
        )
    )
    parser.add_argument(
        "database",
        nargs="?",
        type=Path,
        default=DEFAULT_DATABASE,
        help=f"Path to domain.db (default: {DEFAULT_DATABASE})",
    )
    args = parser.parse_args()
    database = args.database.resolve()
    if not database.is_file():
        parser.error(f"Database not found: {database}")

    database_guids = load_database_guids(database)
    known_guids = {
        guid.casefold()
        for guid in OBJECT_TYPE_RIGHTS
    }
    missing = {
        guid: count
        for guid, count in database_guids.items()
        if guid.casefold() not in known_guids
    }

    print(f"Database: {database}")
    print(f"Constants: {CONSTANTS_DIR / 'constants.py'}")
    print(f"Unique object ACE GUIDs in database: {len(database_guids)}")
    print(f"Known GUIDs in OBJECT_TYPE_RIGHTS: {len(known_guids)}")
    print_section("GUIDs missing from constants.py", missing, missing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
