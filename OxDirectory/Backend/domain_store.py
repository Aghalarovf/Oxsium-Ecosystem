import json
import os
import re
import sqlite3
import hashlib
from datetime import datetime, timezone
from contextlib import contextmanager

from config import DATABASE_PATH, DOMAIN_DATABASE_PATH, EXCEPTION_FILE_PATH, FILES_DIR

_RESERVED_FILENAMES = {
    os.path.basename(DOMAIN_DATABASE_PATH).lower(),
    os.path.basename(DATABASE_PATH).lower(),
    os.path.basename(EXCEPTION_FILE_PATH).lower(),
}


def _is_importable(name):
    lower = name.lower()
    if lower in _RESERVED_FILENAMES:
        return False
    if lower.endswith((".db", ".sqlite", ".sqlite3", "-wal", "-shm", "-journal")):
        return False
    return lower.endswith((".jsonl", ".json"))


def get_exceptions():
    if not os.path.isfile(EXCEPTION_FILE_PATH):
        return []
    try:
        with open(EXCEPTION_FILE_PATH, "r", encoding="utf-8") as source:
            values = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read exception file: {error}") from error
    if not isinstance(values, list):
        raise ValueError("Exception file must contain a JSON array")
    normalized = []
    for value in values:
        if isinstance(value, str) and value.strip():
            normalized.append({"principal_name": value.strip(), "principal_sid": ""})
        elif isinstance(value, dict):
            name = value.get("principal_name", "")
            sid = value.get("principal_sid", "")
            if isinstance(name, str) and isinstance(sid, str) and (name.strip() or sid.strip()):
                normalized.append({
                    "principal_name": name.strip(),
                    "principal_sid": sid.strip(),
                })
        else:
            raise ValueError("Each exception must contain principal_name and principal_sid")
    return sorted(
        {(item["principal_name"].casefold(), item["principal_sid"].casefold()): item for item in normalized}.values(),
        key=lambda item: (item["principal_name"].casefold(), item["principal_sid"].casefold()),
    )


def set_exceptions(values):
    if not isinstance(values, list):
        raise ValueError("Exceptions must be a list")
    normalized = []
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("Each exception must contain principal_name and principal_sid")
        name = value.get("principal_name", "")
        sid = value.get("principal_sid", "")
        if not isinstance(name, str) or not isinstance(sid, str) or not (name.strip() or sid.strip()):
            raise ValueError("Each exception must contain principal_name and principal_sid")
        normalized.append({"principal_name": name.strip(), "principal_sid": sid.strip()})
    normalized = sorted(
        {(item["principal_name"].casefold(), item["principal_sid"].casefold()): item for item in normalized}.values(),
        key=lambda item: (item["principal_name"].casefold(), item["principal_sid"].casefold()),
    )
    temporary = f"{EXCEPTION_FILE_PATH}.tmp"
    with open(temporary, "w", encoding="utf-8") as target:
        json.dump(normalized, target, ensure_ascii=False, indent=2)
        target.write("\n")
    os.replace(temporary, EXCEPTION_FILE_PATH)
    return normalized


def find_ace_principal(value):
    term = value.strip()
    if not term:
        return None
    identity_fields = (
        "principal_name", "principal_sid", "username", "sid",
        "group_name", "group_sid", "computer_name", "dns_name", "name",
    )
    with _domain_connection() as connection:
        candidates = []
        for table in _domain_tables(connection):
            if table == "domain_aces":
                attributes = {field: {"column_name": field} for field in identity_fields}
            else:
                attributes = _attribute_map(connection, table)
            present = [field for field in identity_fields if field in attributes]
            if not present:
                continue
            clauses = [
                f"LOWER(CAST({_quote_identifier(attributes[field]['column_name'])} AS TEXT)) = LOWER(?)"
                for field in present
            ]
            selected = ", ".join(
                f"{_quote_identifier(attributes[field]['column_name'])} AS {_quote_identifier(field)}"
                for field in present
            )
            for row in connection.execute(
                f"SELECT {selected} FROM {table} WHERE {' OR '.join(clauses)} LIMIT 10",
                [term] * len(present),
            ):
                name = next((row[field] for field in ("principal_name", "username", "group_name", "computer_name", "name")
                             if field in present and row[field]), "")
                sid = next((row[field] for field in ("principal_sid", "sid", "group_sid")
                            if field in present and row[field]), "")
                candidates.append({"principal_name": name or "", "principal_sid": sid or ""})
        if candidates:
            return candidates[0]
    return None


def optimize_exceptions():
    exceptions = get_exceptions()
    optimized = []
    unresolved = []
    for exception in exceptions:
        principal = find_ace_principal(exception["principal_name"])
        if principal is None:
            optimized.append(exception)
            unresolved.append(exception["principal_name"])
            continue
        optimized.append({
            "principal_name": exception["principal_name"],
            "principal_sid": principal["principal_sid"],
        })
    return set_exceptions(optimized), unresolved


def _exception_sql(attributes, exceptions):
    columns = [
        _quote_identifier(mapping["column_name"])
        for mapping in attributes.values()
    ]
    clauses = []
    values = []
    if not columns:
        return "", []
    for exception in exceptions:
        checks = []
        for field in ("principal_name", "principal_sid"):
            value = exception.get(field, "").casefold()
            if not value:
                continue
            checks.extend(
                f"instr(LOWER(COALESCE(CAST({column} AS TEXT), '')), ?) > 0"
                for column in columns
            )
            values.extend([value] * len(columns))
        if checks:
            clauses.append(f"NOT ({' OR '.join(checks)})")
    return " AND ".join(clauses), values

DOMAIN_TABLES = (
    "domain_info",
    "domain_users",
    "domain_groups",
    "domain_computers",
    "domain_ous",
    "domain_gpos",
    "domain_trusts",
    "domain_certificates",
)


@contextmanager
def _domain_connection():
    connection = sqlite3.connect(DOMAIN_DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS domain_attributes ("
            "table_name TEXT NOT NULL, attribute_name TEXT NOT NULL, "
            "column_name TEXT NOT NULL, value_type TEXT NOT NULL, "
            "PRIMARY KEY (table_name, attribute_name), "
            "UNIQUE (table_name, column_name))"
        )
        for table in DOMAIN_TABLES:
            _ensure_domain_table(connection, table)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS domain_aces ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "source_name TEXT NOT NULL, "
            "line_number INTEGER NOT NULL, "
            "target_name TEXT, target_dn TEXT, target_sid TEXT, target_type TEXT, "
            "principal_sid TEXT, principal_name TEXT, principal_scope TEXT, object_acetype TEXT, "
            "ace_type_raw INTEGER, rights TEXT NOT NULL, dangerous_ace INTEGER NOT NULL, "
            "extended_rights INTEGER NOT NULL, ace_flags INTEGER)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_aces_group "
            "ON domain_aces (target_dn, target_sid, principal_sid)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_domain_aces_flags "
            "ON domain_aces (dangerous_ace, extended_rights, ace_type_raw)"
        )
        ace_columns = {row[1] for row in connection.execute("PRAGMA table_info(domain_aces)")}
        if "principal_name" not in ace_columns:
            connection.execute("ALTER TABLE domain_aces ADD COLUMN principal_name TEXT")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS files ("
            "name TEXT PRIMARY KEY, size INTEGER NOT NULL, modified_at REAL NOT NULL, "
            "kind TEXT NOT NULL, record_count INTEGER)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS file_contents ("
            "name TEXT PRIMARY KEY, content TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS vulnerability_categories ("
            "vulnerability_id TEXT PRIMARY KEY, category TEXT NOT NULL, "
            "updated_at TEXT NOT NULL)"
        )
        connection.commit()
        yield connection
    finally:
        connection.close()


def _file_kind(name):
    stem = os.path.splitext(name.lower())[0]
    if stem.startswith("domain_"):
        return stem
    if name.lower().endswith(".jsonl"):
        return f"domain_{stem}"
    if name.lower().endswith(".json"):
        return "json"
    return "file"


def _domain_table(kind):
    if kind in DOMAIN_TABLES:
        return kind
    if re.fullmatch(r"domain_[a-z0-9_]+", kind):
        return kind
    return None


def _ensure_domain_table(connection, table):
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {table} ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "source_name TEXT NOT NULL, "
        "line_number INTEGER NOT NULL)"
    )
    columns = {
        row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if "data" in columns:
        legacy_rows = connection.execute(
            f"SELECT id, data FROM {table} ORDER BY id"
        ).fetchall()
        for row in legacy_rows:
            value = json.loads(row["data"])
            if not isinstance(value, dict):
                raise ValueError(f"Stored record in {table} is not an object")
            _ensure_attribute_columns(connection, table, [value])
        for row in legacy_rows:
            value = json.loads(row["data"])
            _update_record_attributes(connection, table, row["id"], value)
        connection.execute(f"ALTER TABLE {table} DROP COLUMN data")


def _quote_identifier(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def _attribute_type(value):
    if isinstance(value, bool):
        return "INTEGER"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "REAL"
    if isinstance(value, (dict, list)):
        return "JSON"
    return "TEXT"


def _attribute_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return int(value)
    return value


def _decode_attribute(value, value_type):
    if value_type == "JSON" or (
        value_type == "TEXT"
        and isinstance(value, str)
        and value[:1] in ("[", "{")
    ):
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            pass
    return value


def _attribute_column_name(table, attribute_name):
    base = re.sub(r"[^a-zA-Z0-9_]", "_", attribute_name).strip("_").lower() or "attribute"
    digest = hashlib.sha1(attribute_name.encode("utf-8")).hexdigest()[:8]
    return f"attr_{base}_{digest}"


def _ensure_attribute_columns(connection, table, records):
    existing = {
        row["attribute_name"]: dict(row)
        for row in connection.execute(
            "SELECT attribute_name, column_name, value_type FROM domain_attributes "
            "WHERE table_name = ?",
            (table,),
        ).fetchall()
    }
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    mapped_columns = {mapping["column_name"] for mapping in existing.values()}
    for record in records:
        for attribute_name, value in record.items():
            if attribute_name in existing:
                continue
            column_name = _attribute_column_name(table, attribute_name)
            if column_name in mapped_columns:
                suffix = hashlib.sha1(
                    f"{table}:{attribute_name}".encode("utf-8")
                ).hexdigest()[:8]
                column_name = f"{column_name}_{suffix}"
                while column_name in columns:
                    suffix = hashlib.sha1(
                        f"{table}:{attribute_name}:{suffix}".encode("utf-8")
                    ).hexdigest()[:8]
                    column_name = f"{_attribute_column_name(table, attribute_name)}_{suffix}"
            elif column_name not in columns:
                orphan_columns = [
                    candidate for candidate in columns
                    if candidate.startswith(f"{column_name}_")
                    and candidate not in mapped_columns
                ]
                column_name = orphan_columns[0] if orphan_columns else column_name
            value_type = _attribute_type(value) if value is not None else "TEXT"
            if column_name not in columns:
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {_quote_identifier(column_name)} {value_type}"
                )
                columns.add(column_name)
            connection.execute(
                "INSERT INTO domain_attributes "
                "(table_name, attribute_name, column_name, value_type) VALUES (?, ?, ?, ?)",
                (table, attribute_name, column_name, value_type),
            )
            existing[attribute_name] = {
                "attribute_name": attribute_name,
                "column_name": column_name,
                "value_type": value_type,
            }
            mapped_columns.add(column_name)


def _attribute_map(connection, table):
    return {
        row["attribute_name"]: dict(row)
        for row in connection.execute(
            "SELECT attribute_name, column_name, value_type FROM domain_attributes "
            "WHERE table_name = ? ORDER BY attribute_name",
            (table,),
        ).fetchall()
    }


def _update_record_attributes(connection, table, record_id, record):
    attributes = _attribute_map(connection, table)
    assignments = []
    values = []
    for attribute_name, mapping in attributes.items():
        if attribute_name in record:
            assignments.append(f"{_quote_identifier(mapping['column_name'])} = ?")
            values.append(_attribute_value(record[attribute_name]))
    if assignments:
        connection.execute(
            f"UPDATE {table} SET {', '.join(assignments)} WHERE id = ?",
            values + [record_id],
        )


def _domain_tables(connection):
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'domain_%'"
    ).fetchall()
    return [
        row["name"] for row in rows
        if row["name"] in DOMAIN_TABLES or row["name"] == "domain_aces"
    ]


def _read_domain_aces(path):
    records = []
    with open(path, "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Line {line_number} is not a JSON object")
            if line_number == 1 and {"generated_at", "count", "meta"} <= set(value):
                continue
            rights = value.get("rights", [])
            if not isinstance(rights, list) or not all(isinstance(item, str) for item in rights):
                raise ValueError(f"Line {line_number} has invalid rights")
            records.append({
                "source_name": os.path.basename(path),
                "line_number": line_number,
                "target_name": value.get("target_name"),
                "target_dn": value.get("target_dn"),
                "target_sid": value.get("target_sid"),
                "target_type": value.get("target_type"),
                "principal_sid": value.get("principal_sid"),
                "principal_name": value.get("principal_name"),
                "principal_scope": value.get("principal_scope"),
                "object_acetype": value.get("object_acetype"),
                "ace_type_raw": value.get("ace_type_raw"),
                "rights": json.dumps(rights, ensure_ascii=False),
                "dangerous_ace": int(bool(value.get("dangerous_ace"))),
                "extended_rights": int(bool(value.get("extended_rights"))),
                "ace_flags": value.get("ace_flags"),
            })
    return records


def import_file(name):
    if not _is_importable(name):
        raise ValueError(f"{name} is not an importable jsonl/json file")
    path = os.path.join(FILES_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(name)
    stat = os.stat(path)
    kind = _file_kind(name)
    records = _read_domain_aces(path) if kind == "domain_aces" else None
    generic_records = None if records is not None else _read_jsonl(path)
    with open(path, "r", encoding="utf-8") as source:
        content = source.read()
    with _domain_connection() as connection:
        connection.execute("DELETE FROM domain_aces WHERE source_name = ?", (name,))
        connection.execute("DELETE FROM file_contents WHERE name = ?", (name,))
        if records is not None:
            connection.executemany(
                "INSERT INTO domain_aces (source_name, line_number, target_name, target_dn, "
                "target_sid, target_type, principal_sid, principal_name, principal_scope, object_acetype, "
                "ace_type_raw, rights, dangerous_ace, extended_rights, ace_flags) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(
                    item["source_name"], item["line_number"], item["target_name"], item["target_dn"],
                    item["target_sid"], item["target_type"], item["principal_sid"],
                    item["principal_name"], item["principal_scope"], item["object_acetype"], item["ace_type_raw"],
                    item["rights"], item["dangerous_ace"], item["extended_rights"], item["ace_flags"],
                ) for item in records],
            )
        elif generic_records is not None:
            table = _domain_table(kind)
            if table:
                _ensure_domain_table(connection, table)
                _ensure_attribute_columns(
                    connection, table, [value for _, value in generic_records]
                )
                connection.execute(f"DELETE FROM {table} WHERE source_name = ?", (name,))
                attributes = _attribute_map(connection, table)
                columns = ["source_name", "line_number"] + [
                    mapping["column_name"] for mapping in attributes.values()
                ]
                placeholders = ",".join("?" for _ in columns)
                quoted_columns = ",".join(_quote_identifier(column) for column in columns)
                connection.executemany(
                    f"INSERT INTO {table} ({quoted_columns}) VALUES ({placeholders})",
                    [
                        (name, line_number)
                        + tuple(_attribute_value(value.get(attribute_name))
                                for attribute_name, mapping in attributes.items())
                        for line_number, value in generic_records
                    ],
                )
        connection.execute(
            "INSERT INTO files (name, size, modified_at, kind, record_count) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET size=excluded.size, modified_at=excluded.modified_at, "
            "kind=excluded.kind, record_count=excluded.record_count",
            (name, stat.st_size, stat.st_mtime, kind,
             len(records) if records is not None else len(generic_records)),
        )
        connection.execute(
            "INSERT INTO file_contents (name, content) VALUES (?, ?)",
            (name, content),
        )
        connection.commit()
    return len(records) if records is not None else len(generic_records)


def _read_jsonl(path):
    records = []
    with open(path, "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict) and line_number == 1 and {"generated_at", "count", "meta"} <= set(value):
                continue
            if not isinstance(value, dict):
                raise ValueError(f"Line {line_number} is not a JSON object")
            records.append((line_number, value))
    return records


def sync_files():
    for entry in os.scandir(FILES_DIR):
        if not entry.is_file() or not _is_importable(entry.name):
            continue
        stat = entry.stat()
        current = get_file(entry.name)
        if (
            current
            and current["size"] == stat.st_size
            and current["modified_at"] == stat.st_mtime
            and current["kind"] == _file_kind(entry.name)
            and (current["kind"] == "domain_aces" or current["record_count"] is not None)
            and get_file_content(entry.name) is not None
        ):
            table = "domain_aces" if current["kind"] == "domain_aces" else _domain_table(current["kind"])
            if table:
                with _domain_connection() as domain_connection:
                    stored = domain_connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE source_name = ?",
                        (entry.name,),
                    ).fetchone()[0]
                if stored == current["record_count"]:
                    continue
            else:
                continue
        import_file(entry.name)
    with _domain_connection() as connection:
        names = {
            entry.name for entry in os.scandir(FILES_DIR)
            if entry.is_file() and _is_importable(entry.name)
        }
        rows = connection.execute("SELECT name FROM files").fetchall()
        for row in rows:
            if row["name"] not in names:
                connection.execute("DELETE FROM domain_aces WHERE source_name = ?", (row["name"],))
                connection.execute("DELETE FROM file_contents WHERE name = ?", (row["name"],))
                connection.execute("DELETE FROM files WHERE name = ?", (row["name"],))
        connection.commit()
    with _domain_connection() as connection:
        for table in _domain_tables(connection):
            placeholders = ",".join("?" for _ in names)
            if names:
                connection.execute(
                    f"DELETE FROM {table} WHERE source_name NOT IN ({placeholders})",
                    tuple(names),
                )
            else:
                connection.execute(f"DELETE FROM {table}")
        connection.commit()


def list_files():
    sync_files()
    with _domain_connection() as connection:
        rows = connection.execute(
            "SELECT name, size, modified_at, kind, record_count FROM files ORDER BY name"
        ).fetchall()
    return [dict(row) for row in rows]


def get_file(name):
    with _domain_connection() as connection:
        row = connection.execute(
            "SELECT name, size, modified_at, kind, record_count FROM files WHERE name = ?",
            (name,),
        ).fetchone()
    return dict(row) if row else None


def get_file_content(name):
    with _domain_connection() as connection:
        row = connection.execute(
            "SELECT content FROM file_contents WHERE name = ?", (name,)
        ).fetchone()
    return row["content"] if row else None


ACE_RIGHT_SEVERITY = {
    "GenericAll": 100,
    "WriteDACL": 95,
    "DS-Replication-Get-Changes-All": 92,
    "WriteOwner": 90,
    "GenericWrite": 85,
    "All-Extended-Rights": 80,
    "Write-msDS-KeyCredentialLink": 75,
    "Write-msDS-AllowedToActOnBehalfOfOtherIdentity": 75,
    "DS-Replication-Synchronize": 70,
    "Write-userAccountControl": 65,
    "DS-Replication-Get-Changes": 60,
    "Validated-Write-SPN": 60,
    "ExtendedRights": 55,
    "Validated-Write-Computer": 50,
    "DS-Replication-Manage-Topology": 50,
    "Apply-Group-Policy": 50,
    "Send-As": 45,
    "Receive-As": 40,
    "Delete": 40,
    "DeleteTree": 40,
    "DeleteChild": 40,
    "CreateChild": 40,
    "Validated-DNS-Host-Name": 35,
    "ChangePassword": 30,
}
ACE_DENY_TYPES = (1, 6)
_ace_group_cache = {"signature": None, "groups": []}


def _ace_row_to_item(row):
    item = dict(row)
    item["rights"] = json.loads(item["rights"])
    item["dangerous_ace"] = bool(item["dangerous_ace"])
    item["extended_rights"] = bool(item["extended_rights"])
    item["is_deny"] = item.get("ace_type_raw") in ACE_DENY_TYPES
    return item


def _ace_severity_key(item):
    default = 20 if item["dangerous_ace"] else 5
    top = max((ACE_RIGHT_SEVERITY.get(right, default) for right in item["rights"]), default=0)
    return (
        1 if item["dangerous_ace"] else 0,
        0 if item["is_deny"] else 1,
        top,
        len(item["rights"]),
        1 if item["extended_rights"] else 0,
        -item["id"],
    )


def _build_ace_groups(connection, rows=None):
    grouped = {}
    source = rows if rows is not None else connection.execute("SELECT * FROM domain_aces ORDER BY id")
    for row in source:
        item = _ace_row_to_item(row)
        key = (item["target_dn"], item["target_sid"], item["principal_sid"])
        grouped.setdefault(key, []).append(item)
    groups = []
    for aces in grouped.values():
        aces.sort(key=_ace_severity_key, reverse=True)
        top = aces[0]
        principal_name = next((ace["principal_name"] for ace in aces if ace.get("principal_name")), None)
        for ace in aces:
            ace["principal_name"] = principal_name
        blob = " ".join(
            [str(top["target_name"] or ""), str(top["target_dn"] or ""), str(top["principal_sid"] or ""),
             str(principal_name or "")]
            + [right for ace in aces for right in ace["rights"]]
        ).lower()
        groups.append({"item": {**top, "ace_count": len(aces), "aces": aces}, "blob": blob})
    return groups


def _ace_filter_sql(filters):
    if not isinstance(filters, dict):
        return "", []

    text_fields = {
        "target_name": "target_name",
        "target_dn": "target_dn",
        "target_type": "target_type",
        "target_sid": "target_sid",
        "principal_name": "principal_name",
        "principal_sid": "principal_sid",
        "principal_scope": "principal_scope",
        "rights": "rights",
        "object_acetype": "object_acetype",
    }
    bool_fields = {
        "dangerous_ace": "dangerous_ace",
        "extended_rights": "extended_rights",
        "inherited": "(ace_flags & 16)",
        "has_target_dn": "target_dn",
        "has_principal_name": "principal_name",
        "is_deny": "ace_type_raw",
    }
    num_fields = {"ace_type_raw": "ace_type_raw", "ace_flags": "ace_flags"}
    clauses = []
    values = []

    def text_clause(column, op, value):
        expression = f"LOWER(COALESCE(CAST({column} AS TEXT), ''))"
        term = str(value or "").strip().lower()
        if op == "empty":
            return f"TRIM({expression}) = ''", []
        if op == "filled":
            return f"TRIM({expression}) <> ''", []
        patterns = {
            "equals": f"{expression} = ?",
            "starts": f"{expression} LIKE ?",
            "ends": f"{expression} LIKE ?",
            "excludes": f"{expression} NOT LIKE ?",
            "not_contains": f"{expression} NOT LIKE ?",
            "not_equals": f"{expression} <> ?",
        }
        if op in patterns:
            parameter = {
                "starts": f"{term}%",
                "ends": f"%{term}",
                "excludes": f"%{term}%",
                "not_contains": f"%{term}%",
            }.get(op, term)
            return patterns[op], [parameter]
        return f"{expression} LIKE ?", [f"%{term}%"]

    def add_text(field, rule):
        column = text_fields.get(field)
        if not column or not isinstance(rule, dict):
            return
        terms = rule.get("values") if isinstance(rule.get("values"), list) else [rule.get("value", "")]
        for term in terms:
            if not str(term or "").strip() and rule.get("op") not in ("empty", "filled"):
                continue
            clause, clause_values = text_clause(column, rule.get("op", "contains"), term)
            clauses.append(clause)
            values.extend(clause_values)

    for field, rule in (filters.get("text") or {}).items():
        add_text(field, rule)

    for field, state in (filters.get("tri") or {}).items():
        if state not in ("yes", "no"):
            continue
        if field == "orphaned_sid":
            expression = (
                "TRIM(COALESCE(principal_name, '')) <> '' "
                "AND TRIM(COALESCE(target_name, '')) <> ''"
            )
            clauses.append(expression if state == "yes" else f"NOT ({expression})")
            continue
        column = bool_fields.get(field)
        if not column:
            continue
        if field == "is_deny":
            expression = f"({column} IN (1, 6))"
        elif field.startswith("has_"):
            expression = f"TRIM(COALESCE(CAST({column} AS TEXT), '')) <> ''"
        else:
            expression = f"COALESCE({column}, 0) <> 0"
        clauses.append(expression if state == "yes" else f"NOT ({expression})")

    for field, rule in (filters.get("num") or {}).items():
        column = num_fields.get(field)
        if not column or not isinstance(rule, dict):
            continue
        if rule.get("min", "") != "":
            clauses.append(f"CAST({column} AS REAL) >= ?")
            values.append(rule["min"])
        if rule.get("max", "") != "":
            clauses.append(f"CAST({column} AS REAL) <= ?")
            values.append(rule["max"])
    for rule in filters.get("rules") or []:
        if not isinstance(rule, dict) or not rule.get("field", "").strip():
            continue
        field = rule["field"].strip()
        if field == "rights":
            column = "rights"
        elif field in text_fields:
            column = text_fields[field]
        elif field in num_fields:
            column = num_fields[field]
        elif field in bool_fields:
            column = bool_fields[field]
        else:
            continue
        op = rule.get("op", "contains")
        if field in ("rights", *text_fields):
            clause, clause_values = text_clause(
                f"CAST({column} AS TEXT)", op, rule.get("value", "")
            )
            clauses.append(clause)
            values.extend(clause_values)
        elif op in ("gt", "gte", "lt", "lte"):
            operator = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
            clauses.append(f"CAST({column} AS REAL) {operator} ?")
            values.append(rule.get("value", ""))
        elif op in ("true", "false"):
            expression = (
                f"({column} IN (1, 6))"
                if field == "is_deny"
                else f"COALESCE({column}, 0) <> 0"
            )
            clauses.append(expression if op == "true" else f"NOT ({expression})")
        elif op == "empty":
            clauses.append(f"TRIM(COALESCE(CAST({column} AS TEXT), '')) = ''")
        elif op == "filled":
            clauses.append(f"TRIM(COALESCE(CAST({column} AS TEXT), '')) <> ''")

    return ((" AND ".join(clauses), values) if clauses else ("", []))


def list_aces(page, page_size, search="", dangerous_only=False, filters=""):
    page_size = min(max(page_size, 1), 400)
    offset = max(page - 1, 0) * page_size
    try:
        parsed_filters = json.loads(filters) if filters else {}
    except (TypeError, json.JSONDecodeError):
        parsed_filters = {}
    exceptions = get_exceptions()
    exception_enabled = bool(exceptions)
    tri_filters = parsed_filters.get("tri") or {}
    with _domain_connection() as connection:
        conditions, values = _ace_filter_sql(parsed_filters)
        if dangerous_only:
            conditions = f"{conditions} AND " if conditions else ""
            conditions += "dangerous_ace = 1"
        tri_filters = parsed_filters.get("tri") or {}
        deny_filter = tri_filters.get("is_deny")
        hide_deny_by_default = (
            deny_filter != "yes"
            and (
                dangerous_only
                or tri_filters.get("dangerous_ace") == "yes"
                or tri_filters.get("extended_rights") == "yes"
            )
        )
        if hide_deny_by_default:
            conditions = f"{conditions} AND " if conditions else ""
            conditions += "NOT (ace_type_raw IN (1, 6))"
        if exception_enabled and exceptions:
            exception_clauses = []
            exception_values = []
            for exception in exceptions:
                checks = []
                if exception["principal_name"]:
                    checks.append("instr(LOWER(COALESCE(principal_name, '')), ?) > 0")
                    exception_values.append(exception["principal_name"].casefold())
                if exception["principal_sid"]:
                    checks.append("instr(LOWER(COALESCE(principal_sid, '')), ?) > 0")
                    exception_values.append(exception["principal_sid"].casefold())
                if checks:
                    exception_clauses.append(f"NOT ({' OR '.join(checks)})")
            conditions = f"{conditions} AND " if conditions else ""
            conditions += " AND ".join(exception_clauses)
            values.extend(exception_values)
        if search:
            search_clause = "(" + " OR ".join(
                "LOWER(COALESCE(CAST(" + column + " AS TEXT), '')) LIKE ?"
                for column in (
                    "target_name", "target_dn", "target_sid", "principal_sid",
                    "principal_name", "rights",
                )
            ) + ")"
            conditions = f"{conditions} AND {search_clause}" if conditions else search_clause
            values.extend([f"%{search.lower()}%"] * 6)
        where = f"WHERE {conditions}" if conditions else ""
        group_query = (
            "SELECT target_dn, target_sid, principal_sid, MIN(id) AS group_id "
            f"FROM domain_aces {where} "
            "GROUP BY target_dn, target_sid, principal_sid "
            "ORDER BY group_id LIMIT ? OFFSET ?"
        )
        group_rows = connection.execute(
            group_query, values + [page_size + 1, offset]
        ).fetchall()
        has_more = len(group_rows) > page_size
        group_rows = group_rows[:page_size]
        total = offset + len(group_rows) + (1 if has_more else 0)
        if not group_rows:
            return [], total, False
        page_conditions = []
        page_values = []
        for group in group_rows:
            page_conditions.append(
                "(target_dn IS ? AND target_sid IS ? AND principal_sid IS ?)"
            )
            page_values.extend([
                group["target_dn"], group["target_sid"], group["principal_sid"]
            ])
        page_where = "(" + " OR ".join(page_conditions) + ")"
        if conditions:
            page_where = f"({conditions}) AND {page_where}"
        rows = connection.execute(
            f"SELECT * FROM domain_aces WHERE {page_where} ORDER BY id",
            values + page_values,
        ).fetchall()
        groups = _build_ace_groups(connection, rows)
    selected = [group["item"] for group in groups]
    return selected, total, has_more


def ace_summary():
    with _domain_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total, SUM(dangerous_ace) AS dangerous, "
            "SUM(extended_rights) AS extended FROM domain_aces"
        ).fetchone()
    return {
        "total": row["total"] or 0,
        "dangerous": row["dangerous"] or 0,
        "extended": row["extended"] or 0,
    }


VULNERABILITY_CATEGORIES = ("Vulnerability Scanner", "Post Exploitation")


def _vulnerability_id(kind, target, detail):
    value = f"{kind}|{target}|{detail}"
    return f"{kind}:{hashlib.sha1(value.encode('utf-8')).hexdigest()[:16]}"


def list_vulnerabilities():
    vulnerabilities = []

    def add(kind, target, title, detail, severity, source):
        vulnerabilities.append({
            "id": _vulnerability_id(kind, target, detail),
            "kind": kind,
            "title": title,
            "target": target or "Unknown",
            "detail": detail,
            "severity": severity,
            "source": source,
        })

    with _domain_connection() as connection:
        for row in connection.execute("SELECT * FROM domain_aces WHERE dangerous_ace = 1 ORDER BY id"):
            target = row["target_name"] or row["target_dn"] or row["target_sid"]
            add(
                "ace",
                target,
                "Dangerous access control entry",
                f"{row['principal_name'] or row['principal_sid'] or 'Unknown principal'} → {row['rights']}",
                "High",
                row["source_name"],
            )

        for table, wanted in (
            ("domain_users", ("username", "display_name", "dn", "kerberoastable", "asrep", "dcsync")),
            ("domain_computers", ("computer_name", "dns_name", "dn", "unconstrained_delegation", "rbcd_enabled")),
        ):
            attributes = _attribute_map(connection, table)
            present = [name for name in wanted if name in attributes]
            if not present:
                continue
            selected = ",".join(
                f"{_quote_identifier(attributes[name]['column_name'])} AS {_quote_identifier(name)}"
                for name in present
            )
            for row in connection.execute(f"SELECT source_name, line_number, {selected} FROM {table} ORDER BY id"):
                name = row["username"] if "username" in present else row["computer_name"]
                name = name or row["display_name"] if "display_name" in present else name
                if "kerberoastable" in present and row["kerberoastable"]:
                    add("user-kerberoast", name, "Kerberoastable account", "Service principal account can be requested", "High", row["source_name"])
                if "asrep" in present and row["asrep"]:
                    add("user-asrep", name, "AS-REP roastable account", "Pre-authentication is not required", "High", row["source_name"])
                if "dcsync" in present and row["dcsync"]:
                    add("user-dcsync", name, "DCSync privilege", "Account has directory replication privileges", "Critical", row["source_name"])
                if "unconstrained_delegation" in present and row["unconstrained_delegation"]:
                    add("computer-delegation", name, "Unconstrained delegation", "Computer is trusted for unconstrained delegation", "High", row["source_name"])
                if "rbcd_enabled" in present and row["rbcd_enabled"]:
                    add("computer-rbcd", name, "Resource-based constrained delegation", "Resource-based delegation is configured", "Medium", row["source_name"])

        attributes = _attribute_map(connection, "domain_certificates")
        if "esc_findings" in attributes:
            column = _quote_identifier(attributes["esc_findings"]["column_name"])
            name_column = _quote_identifier(attributes.get("name", attributes.get("cn", {"column_name": "id"}))["column_name"])
            for row in connection.execute(
                f"SELECT source_name, {name_column} AS finding_name, {column} AS esc_findings "
                "FROM domain_certificates ORDER BY id"
            ):
                findings = _decode_attribute(row["esc_findings"], attributes["esc_findings"]["value_type"])
                for finding in findings if isinstance(findings, list) else []:
                    rule = finding.get("rule", "ESC finding") if isinstance(finding, dict) else str(finding)
                    add("certificate", row["finding_name"], f"Certificate Services {rule}", str(finding), "High", row["source_name"])

        assignment_rows = connection.execute(
            "SELECT vulnerability_id, category FROM vulnerability_categories"
        ).fetchall()
    assignments = {row["vulnerability_id"]: row["category"] for row in assignment_rows}
    for item in vulnerabilities:
        item["category"] = assignments.get(item["id"], VULNERABILITY_CATEGORIES[0])
    return vulnerabilities


def set_vulnerability_category(vulnerability_id, category):
    if category not in VULNERABILITY_CATEGORIES:
        raise ValueError("Invalid vulnerability category")
    with _domain_connection() as connection:
        connection.execute(
            "INSERT INTO vulnerability_categories (vulnerability_id, category, updated_at) "
            "VALUES (?, ?, ?) ON CONFLICT(vulnerability_id) DO UPDATE SET "
            "category = excluded.category, updated_at = excluded.updated_at",
            (vulnerability_id, category, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()


def _record_summary(records):
    total = len(records)

    def count(field, value=True):
        return sum(1 for item in records if item.get(field) is value)

    return {
        "total": total,
        "admins": count("is_admin"),
        "disabled": count("disabled"),
        "locked": count("locked_out"),
        "kerberoastable": count("kerberoastable"),
        "asrep": count("asrep"),
        "dcsync": count("dcsync"),
        "privileged": count("is_privileged"),
        "empty": count("is_empty"),
        "nested": count("is_nested"),
        "protected": count("is_protected"),
        "servers": count("is_server"),
        "workstations": count("is_workstation"),
        "domain_controllers": count("is_domain_controller"),
        "stale": count("is_stale"),
        "delegation": count("unconstrained_delegation"),
        "linked": sum(1 for item in records if (item.get("linked_count") or 0) > 0),
        "enforced": count("enforced"),
        "high_value": count("highvalue"),
        "gpo_links": sum(1 for item in records if item.get("has_gpo_links")),
    }


def dashboard_summary():
    sync_files()
    with _domain_connection() as connection:
        rows = []
        attribute_maps = {}
        for table in DOMAIN_TABLES:
            attributes = _attribute_map(connection, table)
            attribute_maps[table] = attributes
            selected = ",".join(
                f"{_quote_identifier(mapping['column_name'])} AS {_quote_identifier(attribute_name)}"
                for attribute_name, mapping in attributes.items()
            )
            rows.extend(connection.execute(
                f"SELECT ? AS kind{', ' + selected if selected else ''} FROM {table} ORDER BY id",
                (table,),
            ).fetchall())
        ace_total = connection.execute("SELECT COUNT(*) FROM domain_aces").fetchone()[0]
    with _domain_connection() as connection:
        file_rows = connection.execute(
            "SELECT name, kind, record_count FROM files ORDER BY name"
        ).fetchall()
    grouped = {}
    for row in rows:
        item = {key: row[key] for key in row.keys() if key != "kind" and row[key] is not None}
        for attribute_name, mapping in attribute_maps[row["kind"]].items():
            if attribute_name in item:
                item[attribute_name] = _decode_attribute(
                    item[attribute_name], mapping["value_type"]
                )
        grouped.setdefault(row["kind"], []).append(item)

    domain = (grouped.get("domain_info") or [{}])[0]
    return {
        "domain": {
            "name": domain.get("fqdn") or domain.get("domain_name") or domain.get("netbios_name"),
            "risk_score": domain.get("risk_score", 0) or 0,
            "highest_severity": domain.get("highest_severity", "info"),
            "domain_controllers": len(domain.get("domain_controllers") or []),
            "dns_zones": len(domain.get("dns_zones") or []),
            "anonymous_bind": bool((domain.get("null_anonymous_access") or {}).get("allowed")),
            "ldap_signing": bool((domain.get("ldap_signing") or {}).get("required")),
            "enterprise_ca": bool(domain.get("has_enterprise_ca")),
        },
        "sections": {
            "users": _record_summary(grouped.get("domain_users", [])),
            "groups": _record_summary(grouped.get("domain_groups", [])),
            "computers": _record_summary(grouped.get("domain_computers", [])),
            "ous": _record_summary(grouped.get("domain_ous", [])),
            "gpos": _record_summary(grouped.get("domain_gpos", [])),
            "trusts": _record_summary(grouped.get("domain_trusts", [])),
            "certificates": _record_summary(grouped.get("domain_certificates", [])),
        },
        "files": [
            {"name": row["name"], "kind": row["kind"], "records": row["record_count"] or 0}
            for row in file_rows
        ],
        "aces": {"total": ace_total, **{key: value for key, value in ace_summary().items() if key != "total"}},
    }


RESET_SECTIONS = {
    "domain": "domain_info",
    "aces": "domain_aces",
    "users": "domain_users",
    "groups": "domain_groups",
    "computers": "domain_computers",
    "ous": "domain_ous",
    "gpos": "domain_gpos",
    "trusts": "domain_trusts",
    "certificates": "domain_certificates",
}


def reset_database(sections=None, remove_files=True):
    selected = set(RESET_SECTIONS) if sections is None else set(sections)
    invalid = selected - set(RESET_SECTIONS)
    if invalid or not selected:
        raise ValueError("At least one valid reset section must be selected")
    tables = {RESET_SECTIONS[section] for section in selected}
    file_kinds = tables
    with _domain_connection() as connection:
        for table in tables:
            connection.execute(f"DELETE FROM {table}")
        placeholders = ",".join("?" for _ in tables)
        connection.execute(
            f"DELETE FROM domain_attributes WHERE table_name IN ({placeholders})",
            tuple(tables),
        )
        files = connection.execute(
            f"SELECT name FROM files WHERE kind IN ({placeholders})",
            tuple(file_kinds),
        ).fetchall()
        connection.execute(
            f"DELETE FROM file_contents WHERE name IN "
            f"(SELECT name FROM files WHERE kind IN ({placeholders}))",
            tuple(file_kinds),
        )
        connection.execute(
            f"DELETE FROM files WHERE kind IN ({placeholders})",
            tuple(file_kinds),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("VACUUM")
    if remove_files:
        for row in files:
            path = os.path.join(FILES_DIR, row["name"])
            if os.path.isfile(path) and _is_importable(row["name"]):
                os.remove(path)
    return sorted(selected)


def optimize_database():
    removed = 0
    with _domain_connection() as connection:
        for table in _domain_tables(connection):
            if table == "domain_aces":
                continue
            seen_records = set()
            attributes = _attribute_map(connection, table)
            selected = ",".join(
                f"{_quote_identifier(mapping['column_name'])} AS {_quote_identifier(attribute_name)}"
                for attribute_name, mapping in attributes.items()
            )
            rows = connection.execute(
                f"SELECT id{', ' + selected if selected else ''} FROM {table} ORDER BY id"
            ).fetchall()
            for row in rows:
                key = json.dumps(
                    {attribute_name: row[attribute_name] for attribute_name in attributes},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                if key in seen_records:
                    connection.execute(f"DELETE FROM {table} WHERE id = ?", (row["id"],))
                    removed += 1
                else:
                    seen_records.add(key)
        seen_aces = set()
        rows = connection.execute(
            "SELECT * FROM domain_aces ORDER BY id"
        ).fetchall()
        ace_fields = (
            "target_name", "target_dn", "target_sid", "target_type",
            "principal_sid", "principal_name", "principal_scope", "object_acetype", "ace_type_raw",
            "rights", "dangerous_ace", "extended_rights", "ace_flags",
        )
        for row in rows:
            key = tuple(row[field] for field in ace_fields)
            if key in seen_aces:
                connection.execute("DELETE FROM domain_aces WHERE id = ?", (row["id"],))
                removed += 1
            else:
                seen_aces.add(key)

        for file_row in connection.execute("SELECT name, kind FROM files").fetchall():
            table = "domain_aces" if file_row["kind"] == "domain_aces" else _domain_table(file_row["kind"])
            if table:
                count = connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE source_name = ?",
                    (file_row["name"],),
                ).fetchone()[0]
                connection.execute(
                    "UPDATE files SET record_count = ? WHERE name = ?",
                    (count, file_row["name"]),
                )
        connection.commit()
    return removed


def _record_filter_sql(attributes, filters):
    if not isinstance(filters, dict):
        return "", []
    clauses = []
    values = []
    columns = {
        name: _quote_identifier(mapping["column_name"])
        for name, mapping in attributes.items()
    }

    def add_text(field, rule):
        column = columns.get(field)
        if not column or not isinstance(rule, dict):
            return
        op = rule.get("op", "contains")
        value = str(rule.get("value", "")).strip().lower()
        expression = f"LOWER(COALESCE(CAST({column} AS TEXT), ''))"
        if op == "empty":
            clauses.append(f"TRIM({expression}) = ''")
        elif op == "filled":
            clauses.append(f"TRIM({expression}) <> ''")
        else:
            operator = {
                "equals": "=",
                "not_equals": "<>",
                "starts": "LIKE",
                "ends": "LIKE",
                "excludes": "NOT LIKE",
                "not_contains": "NOT LIKE",
            }.get(op, "LIKE")
            pattern = {
                "starts": f"{value}%",
                "ends": f"%{value}",
                "excludes": f"%{value}%",
                "not_contains": f"%{value}%",
            }.get(op, value if op in ("equals", "not_equals") else f"%{value}%")
            clauses.append(f"{expression} {operator} ?")
            values.append(pattern)

    for field, rule in (filters.get("text") or {}).items():
        add_text(field, rule)
    for field, state in (filters.get("tri") or {}).items():
        column = columns.get(field)
        if column and state in ("yes", "no"):
            expression = f"COALESCE({column}, 0) <> 0"
            clauses.append(expression if state == "yes" else f"NOT ({expression})")
    for field, rule in (filters.get("num") or {}).items():
        column = columns.get(field)
        if not column or not isinstance(rule, dict):
            continue
        if rule.get("min", "") != "":
            clauses.append(f"CAST({column} AS REAL) >= ?")
            values.append(rule["min"])
        if rule.get("max", "") != "":
            clauses.append(f"CAST({column} AS REAL) <= ?")
            values.append(rule["max"])
    for field, rule in (filters.get("date") or {}).items():
        column = columns.get(field)
        if not column or not isinstance(rule, dict):
            continue
        expression = f"datetime(CAST({column} AS TEXT))"
        if rule.get("from"):
            clauses.append(f"{expression} >= datetime(?)")
            values.append(rule["from"])
        if rule.get("to"):
            clauses.append(f"{expression} <= datetime(?)")
            values.append(rule["to"])
        if rule.get("within", "") != "":
            clauses.append(f"{expression} >= datetime('now', ?)")
            values.append(f"-{rule['within']} days")
        if rule.get("older", "") != "":
            clauses.append(f"{expression} < datetime('now', ?)")
            values.append(f"-{rule['older']} days")
    membership = filters.get("membership") or {}
    membership_column = columns.get("member_of")
    if membership_column and isinstance(membership, dict):
        for key, negate in (("include", False), ("exclude", True)):
            for term in membership.get(key) or []:
                clause = f"LOWER(CAST({membership_column} AS TEXT)) LIKE ?"
                clauses.append(f"NOT ({clause})" if negate else clause)
                values.append(f"%{str(term).lower()}%")
    for rule in filters.get("rules") or []:
        if not isinstance(rule, dict) or not rule.get("field", "").strip():
            continue
        field = rule["field"].strip()
        if field in columns:
            add_text(field, rule)
    return " AND ".join(clauses), values


def list_records(kind, page, page_size, search="", sort_by=None, sort_dir="desc", filters=""):
    page_size = min(max(page_size, 1), 200)
    offset = max(page - 1, 0) * page_size
    table = _domain_table(kind)
    if table is None:
        return [], 0
    with _domain_connection() as connection:
        attributes = _attribute_map(connection, kind)
        values = []
        conditions = []
        exceptions = get_exceptions()
        exception_sql, exception_values = _exception_sql(attributes, exceptions)
        if exception_sql:
            conditions.append(exception_sql)
            values.extend(exception_values)
        if search:
            search_columns = [
                f"CAST({_quote_identifier(mapping['column_name'])} AS TEXT) LIKE ?"
                for mapping in attributes.values()
            ]
            if search_columns:
                conditions.append("(" + " OR ".join(search_columns) + ")")
                values.extend([f"%{search}%"] * len(search_columns))
        try:
            parsed_filters = json.loads(filters) if filters else {}
        except (TypeError, json.JSONDecodeError):
            parsed_filters = {}
        filter_sql, filter_values = _record_filter_sql(attributes, parsed_filters)
        if filter_sql:
            conditions.append(filter_sql)
            values.extend(filter_values)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        selected = ",".join(
            f"{_quote_identifier(mapping['column_name'])} AS {_quote_identifier(attribute_name)}"
            for attribute_name, mapping in attributes.items()
        )
        order = "id"
        if sort_by and sort_by in attributes:
            direction = "ASC" if str(sort_dir).lower() == "asc" else "DESC"
            column = _quote_identifier(attributes[sort_by]["column_name"])
            order = f"CAST({column} AS INTEGER) {direction}, id"
        total = connection.execute(
            f"SELECT COUNT(*) FROM {table}{where}", values
        ).fetchone()[0]
        rows = connection.execute(
            f"SELECT line_number{', ' + selected if selected else ''} FROM {table}{where} "
            f"ORDER BY {order} LIMIT ? OFFSET ?",
            values + [page_size, offset],
        ).fetchall()
    items = []
    for row in rows:
        record = {
            attribute_name: row[attribute_name]
            for attribute_name in attributes
            if row[attribute_name] is not None
        }
        for attribute_name, mapping in attributes.items():
            if attribute_name in record:
                record[attribute_name] = _decode_attribute(
                    record[attribute_name], mapping["value_type"]
                )
        items.append({"line_number": row["line_number"], "data": record})
    return items, total


def _parent_dn(dn):
    parts = re.split(r"(?<!\\),", dn or "")
    return ",".join(parts[1:])


def _fetch_attributes(connection, table, wanted, exceptions=None):
    attributes = _attribute_map(connection, table)
    present = [name for name in wanted if name in attributes]
    if not present:
        return []
    selected = ",".join(
        f"{_quote_identifier(attributes[name]['column_name'])} AS {_quote_identifier(name)}"
        for name in present
    )
    conditions, values = _exception_sql(attributes, exceptions or [])
    where = f" WHERE {conditions}" if conditions else ""
    rows = connection.execute(
        f"SELECT {selected} FROM {table}{where} ORDER BY id", values
    ).fetchall()
    return [{name: row[name] for name in present} for row in rows]


def list_ou_objects(ou_dn):
    target = (ou_dn or "").strip().lower()
    if not target:
        return []
    sources = (
        ("ou", "domain_ous", "name", "dn", None),
        ("group", "domain_groups", "group_name", "group_dn", None),
        ("computer", "domain_computers", "computer_name", "dn", None),
        ("user", "domain_users", "username", "dn", "display_name"),
    )
    order = {"ou": 0, "group": 1, "computer": 2, "user": 3}
    items = []
    exceptions = get_exceptions()
    with _domain_connection() as connection:
        for object_type, table, name_field, dn_field, fallback_field in sources:
            wanted = [name_field, dn_field] + ([fallback_field] if fallback_field else [])
            for record in _fetch_attributes(connection, table, wanted, exceptions):
                dn = record.get(dn_field)
                if not dn or _parent_dn(dn).lower() != target:
                    continue
                name = record.get(name_field) or (record.get(fallback_field) if fallback_field else None)
                items.append({"name": name or dn, "type": object_type, "dn": dn})
    items.sort(key=lambda item: (order[item["type"]], str(item["name"]).lower()))
    return items