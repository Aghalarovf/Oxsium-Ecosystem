import json
import re
import sqlite3
import time
from contextlib import contextmanager

from config import WEB_RESULTS_DATABASE_PATH


BASE_COLUMNS = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_name": "TEXT NOT NULL",
    "target": "TEXT NOT NULL",
    "target_kind": "TEXT",
    "registered_domain": "TEXT",
    "profile": "TEXT",
    "status": "TEXT",
    "started_at": "TEXT",
    "finished_at": "TEXT",
    "duration": "REAL",
    "findings_total": "INTEGER NOT NULL DEFAULT 0",
    "critical_count": "INTEGER NOT NULL DEFAULT 0",
    "high_count": "INTEGER NOT NULL DEFAULT 0",
    "medium_count": "INTEGER NOT NULL DEFAULT 0",
    "low_count": "INTEGER NOT NULL DEFAULT 0",
    "info_count": "INTEGER NOT NULL DEFAULT 0",
    "summary_json": "TEXT NOT NULL",
    "errors_json": "TEXT NOT NULL",
    "checks_json": "TEXT NOT NULL",
    "imported_at": "REAL NOT NULL",
}


@contextmanager
def connection():
    conn = sqlite3.connect(WEB_RESULTS_DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _identifier(value):
    return '"' + value.replace('"', '""') + '"'


def _column_name(prefix, value):
    normalized = re.sub(r"[^a-zA-Z0-9_]+", "_", str(value)).strip("_").lower()
    return f"{prefix}_{normalized or 'unknown'}"


def init_db():
    with connection() as conn:
        columns = ", ".join(f"{_identifier(name)} {definition}" for name, definition in BASE_COLUMNS.items())
        conn.execute(f"CREATE TABLE IF NOT EXISTS whois_dns ({columns})")
        conn.commit()


def _ensure_column(conn, name):
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(whois_dns)").fetchall()}
    if name not in existing:
        conn.execute(f"ALTER TABLE whois_dns ADD COLUMN {_identifier(name)} TEXT")


def _json(value):
    return json.dumps(value, ensure_ascii=True, default=str)


def _report_values(report, source_name):
    target = report.get("target") or {}
    summary = report.get("summary") or {}
    counts = summary.get("findings_by_severity") or {}
    module = report.get("modules", {}).get("whois_dns") or {}
    findings = module.get("findings") or []
    checks = module.get("data") or {}
    finding_values = {}
    for finding in findings:
        key = _column_name("finding", finding.get("id", "unknown"))
        finding_values.setdefault(key, []).append(finding)
    check_values = {_column_name("check", name): value for name, value in checks.items()}
    values = {
        "source_name": source_name,
        "target": target.get("host") or target.get("input") or "",
        "target_kind": target.get("kind"),
        "registered_domain": target.get("registered_domain"),
        "profile": report.get("profile"),
        "status": module.get("status"),
        "started_at": report.get("started_at"),
        "finished_at": report.get("finished_at"),
        "duration": report.get("duration"),
        "findings_total": int(summary.get("findings_total") or len(findings)),
        "critical_count": int(counts.get("critical") or 0),
        "high_count": int(counts.get("high") or 0),
        "medium_count": int(counts.get("medium") or 0),
        "low_count": int(counts.get("low") or 0),
        "info_count": int(counts.get("info") or 0),
        "summary_json": _json(summary),
        "errors_json": _json(report.get("errors") or module.get("errors") or []),
        "checks_json": _json(module.get("checks") or []),
        "imported_at": time.time(),
    }
    values.update({key: _json(value) for key, value in check_values.items()})
    values.update({key: _json(value) for key, value in finding_values.items()})
    return values


def import_report(report, source_name):
    if not isinstance(report, dict):
        raise ValueError("The uploaded file must contain a JSON object")
    if report.get("tool") != "OxWebx":
        raise ValueError("The uploaded file is not an OxWebx report")
    module = (report.get("modules") or {}).get("whois_dns")
    if not isinstance(module, dict):
        raise ValueError("The report does not contain a whois_dns module")
    values = _report_values(report, source_name)
    with connection() as conn:
        for name in values:
            if name not in BASE_COLUMNS:
                _ensure_column(conn, name)
        columns = list(values)
        placeholders = ", ".join("?" for _ in columns)
        query = (
            f"INSERT INTO whois_dns ({', '.join(_identifier(name) for name in columns)}) "
            f"VALUES ({placeholders})"
        )
        cursor = conn.execute(query, [values[name] for name in columns])
        conn.commit()
        return get_report(cursor.lastrowid)


def _decode(row):
    item = dict(row)
    for name in ("summary_json", "errors_json", "checks_json"):
        item[name[:-5]] = json.loads(item.pop(name))
    for name, value in list(item.items()):
        if name.startswith(("check_", "finding_")) and value:
            item[name] = json.loads(value)
    return item


def list_reports():
    with connection() as conn:
        rows = conn.execute("SELECT * FROM whois_dns ORDER BY id DESC").fetchall()
    return [_decode(row) for row in rows]


def get_report(report_id):
    with connection() as conn:
        row = conn.execute("SELECT * FROM whois_dns WHERE id = ?", (report_id,)).fetchone()
    return _decode(row) if row else None


def reset_reports():
    with connection() as conn:
        deleted = conn.execute("DELETE FROM whois_dns").rowcount
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'whois_dns'")
        conn.commit()
        conn.execute("VACUUM")
    return deleted
