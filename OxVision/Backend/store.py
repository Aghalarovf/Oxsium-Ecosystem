import json
import os
import re
import time
import uuid
import ipaddress
import sqlite3
import threading
from contextlib import contextmanager
from config import DATABASE_PATH, CWES_PATH

_dataset = None
_dataset_path = None
_datasets = []
_reset_lock = threading.Lock()
RESULT_TABLES = {"datasets", "subnet_meta", "subnet_groups", "subnet_group_names"}

@contextmanager
def _connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS datasets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "source_name TEXT NOT NULL, "
            "data TEXT NOT NULL, "
            "created_at REAL NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS subnet_meta ("
            "subnet TEXT PRIMARY KEY, "
            "special_name TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS subnet_groups ("
            "subnet TEXT PRIMARY KEY, "
            "group_name TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS subnet_group_names ("
            "group_name TEXT PRIMARY KEY)"
        )
        connection.commit()
        yield connection
    finally:
        connection.close()

def _database_datasets():
    with _connection() as connection:
        rows = connection.execute(
            "SELECT id, source_name, data FROM datasets ORDER BY id"
        ).fetchall()
    return [(json.loads(row["data"]), row["source_name"], row["id"]) for row in rows]

def _replace_dataset(dataset_id, data):
    with _connection() as connection:
        connection.execute(
            "UPDATE datasets SET data = ? WHERE id = ?",
            (json.dumps(data, ensure_ascii=False), dataset_id),
        )
        connection.commit()

def optimize_database():
    removed = 0
    unique_hosts = {}
    host_datasets = {}
    with _reset_lock:
        for data, _, dataset_id in _database_datasets():
            hosts = data.get("hosts")
            if not isinstance(hosts, list):
                continue

            ordered_hosts = []
            for host in hosts:
                if not isinstance(host, dict):
                    ordered_hosts.append(host)
                    continue
                address = str(host.get("host") or "").strip()
                if not address or address not in unique_hosts:
                    unique_hosts[address] = host
                    host_datasets[address] = (dataset_id, data)
                    ordered_hosts.append(host)
                    continue

                existing = unique_hosts[address]
                existing_dataset_id, existing_data = host_datasets[address]
                existing_ports = existing.setdefault("ports", [])
                for port in host.get("ports", []):
                    if port not in existing_ports:
                        existing_ports.append(port)
                existing_roles = existing.setdefault("roles", [])
                for role in host.get("roles", []):
                    if role not in existing_roles:
                        existing_roles.append(role)
                for field in ("hostname", "os", "type", "reason", "note", "subnet", "network", "cidr"):
                    if not existing.get(field) and host.get(field):
                        existing[field] = host[field]
                _replace_dataset(existing_dataset_id, existing_data)
                removed += 1

            if len(ordered_hosts) != len(hosts):
                data["hosts"] = ordered_hosts
                _replace_dataset(dataset_id, data)
        _sync_cache()
    return removed

MAX_SPECIAL_NAME = 40

def clean_special_name(value):
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:MAX_SPECIAL_NAME]

def get_subnet_names():
    with _connection() as connection:
        rows = connection.execute("SELECT subnet, special_name FROM subnet_meta").fetchall()
    return {row["subnet"]: row["special_name"] for row in rows}

def set_subnet_name(subnet, name):
    label = subnet_label(subnet)
    with _connection() as connection:
        if name:
            connection.execute(
                "INSERT INTO subnet_meta (subnet, special_name) VALUES (?, ?) "
                "ON CONFLICT(subnet) DO UPDATE SET special_name = excluded.special_name",
                (label, name),
            )
        else:
            connection.execute("DELETE FROM subnet_meta WHERE subnet = ?", (label,))
        connection.commit()

def clean_group_name(value):
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:MAX_SPECIAL_NAME]

def get_subnet_groups():
    with _connection() as connection:
        rows = connection.execute("SELECT subnet, group_name FROM subnet_groups").fetchall()
    return {row["subnet"]: row["group_name"] for row in rows}

def get_subnet_group_names():
    with _connection() as connection:
        rows = connection.execute("SELECT group_name FROM subnet_group_names").fetchall()
    return [row["group_name"] for row in rows]

def add_subnet_group_name(group_name):
    with _connection() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO subnet_group_names (group_name) VALUES (?)",
            (group_name,),
        )
        connection.commit()

def set_subnet_group(subnet, group_name):
    label = subnet_label(subnet)
    with _connection() as connection:
        if group_name:
            connection.execute(
                "INSERT OR IGNORE INTO subnet_group_names (group_name) VALUES (?)",
                (group_name,),
            )
            connection.execute(
                "INSERT INTO subnet_groups (subnet, group_name) VALUES (?, ?) "
                "ON CONFLICT(subnet) DO UPDATE SET group_name = excluded.group_name",
                (label, group_name),
            )
        else:
            connection.execute("DELETE FROM subnet_groups WHERE subnet = ?", (label,))
        connection.commit()

def delete_subnet_group(subnet):
    with _connection() as connection:
        connection.execute("DELETE FROM subnet_groups WHERE subnet = ?", (subnet_label(subnet),))
        connection.commit()

def _delete_dataset(dataset_id):
    with _connection() as connection:
        connection.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
        connection.commit()

def _sync_cache():
    global _dataset, _dataset_path, _datasets
    datasets = _database_datasets()
    _datasets = [(data, name) for data, name, _ in datasets]
    if datasets:
        _dataset, _dataset_path, _ = datasets[-1]
    else:
        _dataset = None
        _dataset_path = None

def load_dataset(data, path=None):
    global _dataset, _dataset_path, _datasets
    source_name = os.path.basename(path) if path else "dataset.json"
    with _connection() as connection:
        connection.execute(
            "INSERT INTO datasets (source_name, data, created_at) VALUES (?, ?, ?)",
            (source_name, json.dumps(data, ensure_ascii=False), os.path.getmtime(path) if path and os.path.exists(path) else 0),
        )
        connection.commit()
    _dataset = data
    _dataset_path = source_name
    _datasets = [(item, name) for item, name, _ in _database_datasets()]

def load_persisted_datasets(upload_dir):
    global _dataset, _dataset_path, _datasets
    datasets = _database_datasets()
    if not datasets:
        for filename in sorted(os.listdir(upload_dir)):
            if not filename.lower().endswith(".json"):
                continue
            path = os.path.join(upload_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as dataset_file:
                    data = json.load(dataset_file)
                if isinstance(data, dict) and isinstance(data.get("hosts"), list):
                    load_dataset(data, filename)
            except (OSError, ValueError) as error:
                print(f"Could not import persisted dataset {path}: {error}")
        datasets = _database_datasets()
    _datasets = [(data, name) for data, name, _ in datasets]
    if datasets:
        _dataset, _dataset_path, _ = datasets[-1]
    else:
        _dataset = None
        _dataset_path = None

def get_dataset():
    datasets = _database_datasets()
    return datasets[-1][0] if datasets else None

def get_dataset_path():
    datasets = _database_datasets()
    return datasets[-1][1] if datasets else None

def get_subnets():
    subnets = []
    seen = set()
    for data, _, _ in _database_datasets():
        for subnet in data.get("subnets", []):
            key = json.dumps(subnet, ensure_ascii=False, sort_keys=True)
            if key not in seen:
                seen.add(key)
                subnets.append(subnet)
    return subnets

def subnet_label(subnet):
    if isinstance(subnet, str):
        return subnet
    if isinstance(subnet, dict):
        return subnet.get("subnet") or subnet.get("network") or subnet.get("cidr") or json.dumps(
            subnet, ensure_ascii=False, sort_keys=True
        )
    return str(subnet)

def get_hosts(subnet=None, group_name=None):
    hosts = []
    group_subnets = set()
    networks = []
    if group_name:
        group_subnets = {
            label for label, assigned in get_subnet_groups().items()
            if assigned == group_name
        }
        for item in get_subnets():
            label = subnet_label(item)
            try:
                networks.append((label, ipaddress.ip_network(label, strict=False)))
            except ValueError:
                continue
    for data, _, _ in _database_datasets():
        for host in data.get("hosts", []):
            if subnet and not host_matches_subnet(host, subnet):
                continue
            if group_subnets and _host_subnet(host, networks) not in group_subnets:
                continue
            if group_name and not group_subnets:
                continue
            hosts.append(host)
    return hosts


def _host_identifier(host):
    value = host.get("host") or host.get("ip")
    return str(value).strip() if value is not None else ""

def host_matches_subnet(host, subnet):
    requested = subnet_label(subnet)
    host_subnet = host.get("subnet") or host.get("network") or host.get("cidr")
    if host_subnet and str(host_subnet) == requested:
        return True
    try:
        address = ipaddress.ip_address(str(host.get("host")))
        return address in ipaddress.ip_network(requested, strict=False)
    except ValueError:
        return False

def delete_subnet(subnet):
    requested = subnet_label(subnet)
    removed_hosts = 0
    removed_subnets = 0
    for data, _, dataset_id in _database_datasets():
        hosts = data.get("hosts", [])
        subnets = data.get("subnets", [])
        kept_hosts = [host for host in hosts if not host_matches_subnet(host, requested)]
        kept_subnets = [item for item in subnets if subnet_label(item) != requested]
        if len(kept_hosts) == len(hosts) and len(kept_subnets) == len(subnets):
            continue
        removed_hosts += len(hosts) - len(kept_hosts)
        removed_subnets += len(subnets) - len(kept_subnets)
        data["hosts"] = kept_hosts
        if "subnets" in data:
            data["subnets"] = kept_subnets
        if not kept_hosts and not kept_subnets:
            _delete_dataset(dataset_id)
        else:
            _replace_dataset(dataset_id, data)
    if removed_hosts or removed_subnets:
        set_subnet_name(requested, "")
        delete_subnet_group(requested)
    _sync_cache()
    return removed_hosts, removed_subnets

def subnet_host_counts():
    entries = []
    for subnet in get_subnets():
        label = subnet_label(subnet)
        try:
            network = ipaddress.ip_network(label, strict=False)
        except ValueError:
            network = None
        entries.append((label, network))
    counts = {label: 0 for label, _ in entries}
    for host in get_hosts():
        explicit = host.get("subnet") or host.get("network") or host.get("cidr")
        explicit = str(explicit) if explicit else None
        try:
            address = ipaddress.ip_address(str(host.get("host")))
        except ValueError:
            address = None
        for label, network in entries:
            if (explicit and explicit == label) or (network is not None and address is not None and address in network):
                counts[label] += 1
    return counts

def _backup_number():
    directory = os.path.dirname(DATABASE_PATH)
    stem = os.path.splitext(os.path.basename(DATABASE_PATH))[0]
    pattern = re.compile(rf"^{re.escape(stem)}_(\d+)\.db\.bak$")
    used = []
    for name in os.listdir(directory):
        match = pattern.match(name)
        if match:
            used.append(int(match.group(1)))
    return max(used, default=0) + 1

def _copy_accounts(backup_path):
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        connection.execute("ATTACH DATABASE ? AS old", (backup_path,))
        tables = [
            row[0] for row in connection.execute(
                "SELECT name FROM old.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        for table in tables:
            if table in RESULT_TABLES:
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            exists = connection.execute(
                "SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            if not exists:
                create_sql = connection.execute(
                    "SELECT sql FROM old.sqlite_master WHERE type = 'table' AND name = ?", (table,)
                ).fetchone()[0]
                connection.execute(create_sql)
            old_columns = [row[1] for row in connection.execute(f"PRAGMA old.table_info({quoted})")]
            new_columns = [row[1] for row in connection.execute(f"PRAGMA main.table_info({quoted})")]
            shared = ", ".join('"' + c.replace('"', '""') + '"' for c in new_columns if c in old_columns)
            if shared:
                connection.execute(
                    f"INSERT OR IGNORE INTO main.{quoted} ({shared}) SELECT {shared} FROM old.{quoted}"
                )
        connection.commit()
        connection.execute("DETACH DATABASE old")
    finally:
        connection.close()

def _archive_json_files(number):
    directory = os.path.dirname(DATABASE_PATH)
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not (os.path.isfile(path) and name.lower().endswith(".json")):
            continue
        stem = name[:-5]
        suffix = number
        target = os.path.join(directory, f"{stem}_{suffix}.json.bak")
        while os.path.exists(target):
            suffix += 1
            target = os.path.join(directory, f"{stem}_{suffix}.json.bak")
        os.rename(path, target)

def reset_database():
    global _dataset, _dataset_path, _datasets
    with _reset_lock:
        backup = None
        number = None
        if os.path.exists(DATABASE_PATH):
            number = _backup_number()
            stem = os.path.splitext(os.path.basename(DATABASE_PATH))[0]
            backup = os.path.join(os.path.dirname(DATABASE_PATH), f"{stem}_{number}.db.bak")
            os.rename(DATABASE_PATH, backup)
            for suffix in ("-wal", "-shm", "-journal"):
                if os.path.exists(DATABASE_PATH + suffix):
                    os.rename(DATABASE_PATH + suffix, backup + suffix)
        try:
            import users_store
            with _connection():
                pass
            with users_store._connection():
                pass
            if backup:
                _copy_accounts(backup)
        except Exception:
            if backup:
                if os.path.exists(DATABASE_PATH):
                    os.remove(DATABASE_PATH)
                os.rename(backup, DATABASE_PATH)
                for suffix in ("-wal", "-shm", "-journal"):
                    if os.path.exists(backup + suffix):
                        os.rename(backup + suffix, DATABASE_PATH + suffix)
            raise
        _archive_json_files(number or 1)
        _dataset = None
        _dataset_path = None
        _datasets = []
        return backup

DEFAULT_ROLES = [
    "Domain Controller", "Web Server", "Database", "File Server", "Mail Server",
    "DNS Server", "Remote Access", "Printer", "Network Device", "Workstation",
    "Jump Host", "Out of Scope", "Compromised", "High Value",
]
MAX_ROLES = 8
MAX_ROLE_LENGTH = 24
NO_ROLE = "__none__"
SORT_KEYS = {"ip", "os", "ports", "roles"}

def clean_roles(values):
    if not isinstance(values, list):
        return None
    canonical = {role.lower(): role for role in DEFAULT_ROLES}
    cleaned = []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            continue
        name = " ".join(value.replace(",", " ").split())[:MAX_ROLE_LENGTH].strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        cleaned.append(canonical.get(key, name))
        if len(cleaned) >= MAX_ROLES:
            break
    return cleaned

def update_host_field(host_id, key, value):
    host_id = str(host_id)
    return update_host_fields(host_id, {key: value})

def update_host_fields(host_id, fields):
    host_id = str(host_id)
    matches = []
    for data, source_name, dataset_id in _database_datasets():
        changed = False
        for host in data.get("hosts", []):
            if str(host.get("host")) == host_id:
                host.update(fields)
                changed = True
        if changed:
            matches.append((data, source_name, dataset_id))
    if not matches:
        return False
    for data, _, dataset_id in matches:
        _replace_dataset(dataset_id, data)
    global _dataset, _datasets
    _datasets = [(data, name) for data, name, _ in _database_datasets()]
    _dataset = _datasets[-1][0] if _datasets else None
    return True

def host_subnets(hosts):
    networks = []
    for subnet in get_subnets():
        label = subnet_label(subnet)
        try:
            networks.append((label, ipaddress.ip_network(label, strict=False)))
        except ValueError:
            continue
    result = []
    for host in hosts:
        result.append(_host_subnet(host, networks))
    return result

def _host_subnet(host, networks):
    explicit = host.get("subnet") or host.get("network") or host.get("cidr")
    if explicit:
        return str(explicit)
    try:
        address = ipaddress.ip_address(str(host.get("host")))
        for label, network in networks:
            if address in network:
                return label
    except ValueError:
        pass
    return None

def os_label(host):
    return host.get("os") or "Unknown"

def _csv(args, key):
    return [item.strip() for item in (args.get(key) or "").split(",") if item.strip()]

def _parse_port_tokens(args):
    tokens = []
    for token in _csv(args, "port"):
        protocol = None
        if "/" in token:
            token, protocol = token.split("/", 1)
            protocol = protocol.strip().lower() or None
        try:
            if "-" in token:
                low, high = (int(part) for part in token.split("-", 1))
            else:
                low = high = int(token)
        except ValueError:
            continue
        tokens.append((min(low, high), max(low, high), protocol))
    return tokens

def _has_port(host, tokens):
    for port in host.get("ports", []):
        try:
            number = int(port.get("port"))
        except (TypeError, ValueError):
            continue
        protocol = str(port.get("protocol") or "").lower()
        for low, high, wanted in tokens:
            if low <= number <= high and (wanted is None or wanted == protocol):
                return True
    return False

def _haystack(host):
    parts = [
        str(host.get("host") or ""), str(host.get("hostname") or ""),
        str(host.get("os") or ""), str(host.get("note") or ""),
        " ".join(host.get("roles") or []),
    ]
    for port in host.get("ports", []):
        parts.extend([
            str(port.get("port") or ""), str(port.get("service") or ""),
            str(port.get("product") or ""), str(port.get("version") or ""),
        ])
    return " ".join(parts).lower()

def _ip_key(host):
    try:
        address = ipaddress.ip_address(str(host.get("host")))
        return (0, address.version, int(address))
    except ValueError:
        return (1, 0, str(host.get("host")))

def apply_filters(hosts, args):
    terms = (args.get("q") or "").lower().split()
    systems = {item.lower() for item in _csv(args, "os")}
    roles = {item.lower() for item in _csv(args, "role")}
    tokens = _parse_port_tokens(args)
    service = (args.get("service") or "").strip().lower()
    try:
        minimum = int(args.get("min_ports") or 0)
    except ValueError:
        minimum = 0

    result = []
    for host in hosts:
        if systems and os_label(host).lower() not in systems:
            continue
        if roles:
            host_roles = {role.lower() for role in host.get("roles") or []}
            wants_none = NO_ROLE in roles
            if not (host_roles & roles) and not (wants_none and not host_roles):
                continue
        if tokens and not _has_port(host, tokens):
            continue
        if service and not any(
            service in str(port.get("service") or "").lower() for port in host.get("ports", [])
        ):
            continue
        if minimum and len(host.get("ports", [])) < minimum:
            continue
        if terms:
            haystack = _haystack(host)
            if not all(term in haystack for term in terms):
                continue
        result.append(host)
    return result

def sort_hosts(hosts, key, direction):
    if key not in SORT_KEYS:
        return hosts
    keys = {
        "ip": _ip_key,
        "os": lambda h: (os_label(h).lower(), _ip_key(h)),
        "ports": lambda h: (len(h.get("ports", [])), _ip_key(h)),
        "roles": lambda h: (len(h.get("roles") or []), _ip_key(h)),
    }
    return sorted(hosts, key=keys[key], reverse=(direction == "desc"))

def query_hosts(args):
    hosts = apply_filters(get_hosts(args.get("subnet"), args.get("subnet_group")), args)
    return sort_hosts(hosts, args.get("sort"), args.get("dir"))

def filter_options(subnet=None, group_name=None):
    hosts = get_hosts(subnet, group_name)
    systems = {}
    roles = {}
    services = set()
    unassigned = 0
    for host in hosts:
        label = os_label(host)
        systems[label] = systems.get(label, 0) + 1
        host_roles = host.get("roles") or []
        if not host_roles:
            unassigned += 1
        for role in host_roles:
            roles[role] = roles.get(role, 0) + 1
        for port in host.get("ports", []):
            if port.get("service"):
                services.add(str(port["service"]))
    role_options = [
        {"value": name, "label": name, "count": count}
        for name, count in sorted(roles.items(), key=lambda item: (-item[1], item[0].lower()))
    ]
    if unassigned:
        role_options.append({"value": NO_ROLE, "label": "Unassigned", "count": unassigned})
    return {
        "os": [
            {"value": name, "label": name, "count": count}
            for name, count in sorted(systems.items(), key=lambda item: (-item[1], item[0]))
        ],
        "roles": role_options,
        "services": sorted(services, key=str.lower),
    }

# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

MAX_VULN_TITLE = 160
MAX_VULN_TEXT = 8000
MAX_VULN_CVE = 40
MAX_VULNS_PER_HOST = 500
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
VULNERABILITY_CATEGORIES = ("Vulnerability Scanner", "Post Exploitation")
VALID_OPERATING_SYSTEMS = (
    "Unknown",
    "Linux",
    "Windows",
    "Network",
    "Virtual Machine",
    "Gateway",
    "Firewall",
    "Camera",
)

_cwe_index = None
_cwe_lock = threading.Lock()

def _load_cwe_index():
    global _cwe_index
    with _cwe_lock:
        if _cwe_index is not None:
            return _cwe_index
        index = {}
        ordered = []
        try:
            with open(CWES_PATH, "r", encoding="utf-8") as f:
                entries = json.load(f)
            for entry in entries:
                cwe_id = entry.get("id")
                if not cwe_id:
                    continue
                index[cwe_id] = entry
                ordered.append(entry)
        except (OSError, ValueError):
            index = {}
            ordered = []
        _cwe_index = {"by_id": index, "ordered": ordered}
        return _cwe_index

def get_cwe(cwe_id):
    if not cwe_id:
        return None
    label = cwe_id if str(cwe_id).upper().startswith("CWE-") else f"CWE-{cwe_id}"
    return _load_cwe_index()["by_id"].get(label.upper().replace("CWE-", "CWE-"))

def search_cwes(query, limit=25):
    query = (query or "").strip().lower()
    entries = _load_cwe_index()["ordered"]
    if not query:
        results = [e for e in entries if e.get("status") != "Deprecated"][:limit]
        return results
    numeric = query.upper().replace("CWE-", "").strip()
    matches = []
    for entry in entries:
        if entry.get("status") == "Deprecated":
            continue
        id_num = str(entry.get("cwe_id"))
        name = (entry.get("name") or "").lower()
        score = None
        if numeric.isdigit() and id_num == numeric:
            score = 0
        elif query in name:
            score = 1 if name.startswith(query) else 2
        if score is not None:
            matches.append((score, entry))
        if len(matches) >= limit * 4:
            break
    matches.sort(key=lambda item: (item[0], item[1].get("cwe_id", 0)))
    return [entry for _, entry in matches[:limit]]

def clean_severity(value):
    if isinstance(value, str) and value in VALID_SEVERITIES:
        return value
    return None

def clean_vulnerability_input(payload):
    if not isinstance(payload, dict):
        return None, "A JSON object is required"

    title = payload.get("title")
    if not isinstance(title, str) or not title.strip():
        return None, "A 'title' is required"
    title = " ".join(title.split())[:MAX_VULN_TITLE]

    severity = clean_severity(payload.get("severity"))
    if not severity:
        return None, "A valid 'severity' is required (Critical, High, Medium, Low, Info)"

    cve_id = payload.get("cve_id")
    cve_id = cve_id.strip().upper()[:MAX_VULN_CVE] if isinstance(cve_id, str) else ""
    if cve_id and not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return None, "Invalid CVE ID format (expected CVE-YYYY-NNNN)"

    cwe_raw = payload.get("cwe_id")
    cwe_id = None
    if isinstance(cwe_raw, str) and cwe_raw.strip():
        label = cwe_raw.strip().upper()
        if not label.startswith("CWE-"):
            label = f"CWE-{label}"
        if not re.match(r"^CWE-\d+$", label):
            return None, "Invalid CWE ID format (expected CWE-NNN)"
        cwe_id = label

    description = payload.get("description")
    description = description.strip()[:MAX_VULN_TEXT] if isinstance(description, str) else ""

    remediation = payload.get("remediation")
    remediation = remediation.strip()[:MAX_VULN_TEXT] if isinstance(remediation, str) else ""

    poc = payload.get("poc")
    poc = poc.strip()[:MAX_VULN_TEXT] if isinstance(poc, str) else ""

    exploit_commands = payload.get("exploit_commands")
    exploit_commands = exploit_commands.strip()[:MAX_VULN_TEXT] if isinstance(exploit_commands, str) else ""

    affected_service = payload.get("affected_service")
    affected_service = " ".join(affected_service.split())[:200] if isinstance(affected_service, str) else ""

    status = payload.get("status")
    valid_status = {"Open", "In Progress", "Fixed", "False Positive", "Accepted Risk"}
    status = status if isinstance(status, str) and status in valid_status else "Open"

    category = payload.get("category", VULNERABILITY_CATEGORIES[0])
    if category not in VULNERABILITY_CATEGORIES:
        return None, "A valid vulnerability category is required"

    cvss = payload.get("cvss") if isinstance(payload.get("cvss"), dict) else None
    cvss_clean = None
    if cvss:
        vector = cvss.get("vector")
        score = cvss.get("score")
        cvss_severity = cvss.get("severity")
        if isinstance(vector, str) and vector.strip():
            cvss_clean = {
                "version": "3.1",
                "vector": vector.strip()[:120],
                "score": round(float(score), 1) if isinstance(score, (int, float)) else None,
                "severity": cvss_severity if cvss_severity in VALID_SEVERITIES else None,
            }

    return {
        "title": title,
        "severity": severity,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "description": description,
        "remediation": remediation,
        "poc": poc,
        "exploit_commands": exploit_commands,
        "affected_service": affected_service,
        "status": status,
        "category": category,
        "cvss": cvss_clean,
    }, None

def get_vulnerabilities(host_id):
    host_id = str(host_id).strip()
    for host in get_hosts():
        if _host_identifier(host) == host_id:
            return [
                {**vulnerability, "category": vulnerability.get("category", VULNERABILITY_CATEGORIES[0])}
                for vulnerability in host.get("vulnerabilities", []) or []
            ]
    return None  # host not found

def add_vulnerability(host_id, fields):
    host_id = str(host_id).strip()
    record = dict(fields)
    record["id"] = uuid.uuid4().hex
    record["created_at"] = time.time()
    record["updated_at"] = record["created_at"]

    for data, _, dataset_id in _database_datasets():
        changed = False
        for host in data.get("hosts", []):
            if _host_identifier(host) == host_id:
                vulns = host.setdefault("vulnerabilities", [])
                if len(vulns) >= MAX_VULNS_PER_HOST:
                    return None, "Maximum number of vulnerabilities reached for this host"
                vulns.append(record)
                changed = True
        if changed:
            _replace_dataset(dataset_id, data)
            _sync_cache()
            return record, None
    return None, "Host not found"

def update_vulnerability(host_id, vuln_id, fields, target_hosts=None):
    host_id = str(host_id).strip()
    datasets = _database_datasets()
    source_host = None
    source_record = None
    for data, _, _ in datasets:
        source_host = next(
            (host for host in data.get("hosts", []) if _host_identifier(host) == host_id),
            None,
        )
        if source_host is None:
            continue
        source_record = next(
            (vuln for vuln in source_host.get("vulnerabilities", []) if vuln.get("id") == vuln_id),
            None,
        )
        if source_record is not None:
            break
    if source_record is None:
        return None, "Vulnerability not found"

    requested_hosts = [host_id]
    if target_hosts is not None:
        if not isinstance(target_hosts, list):
            return None, "Hosts must be a list"
        requested_hosts.extend(
            str(value).strip() for value in target_hosts if str(value).strip()
        )
    requested_hosts = list(dict.fromkeys(requested_hosts))

    all_hosts = {
        _host_identifier(host): host
        for data, _, _ in datasets
        for host in data.get("hosts", [])
        if _host_identifier(host)
    }
    target_map = {}
    for requested_host in requested_hosts:
        target = all_hosts.get(requested_host)
        if target is None:
            return None, f"Host not found: {requested_host}"
        target_map[requested_host] = target

    new_record = dict(source_record)
    new_record.update(fields)
    new_record["updated_at"] = time.time()
    for requested_host, target in target_map.items():
        vulnerabilities = target.setdefault("vulnerabilities", [])
        existing = next((vuln for vuln in vulnerabilities if vuln.get("id") == vuln_id), None)
        if existing is None:
            if len(vulnerabilities) >= MAX_VULNS_PER_HOST:
                return None, f"Maximum number of vulnerabilities reached for host {requested_host}"
            vulnerabilities.append(dict(new_record))
        else:
            existing.update(new_record)

    if target_hosts is not None:
        requested_set = set(requested_hosts)
        for data, _, _ in datasets:
            for host in data.get("hosts", []):
                if _host_identifier(host) in requested_set:
                    continue
                vulnerabilities = host.get("vulnerabilities")
                if not vulnerabilities:
                    continue
                host["vulnerabilities"] = [
                    vuln for vuln in vulnerabilities if vuln.get("id") != vuln_id
                ]

    for data, _, dataset_id in datasets:
        _replace_dataset(dataset_id, data)
    _sync_cache()
    return new_record, None

def delete_vulnerability(host_id, vuln_id):
    host_id = str(host_id).strip()
    for data, _, dataset_id in _database_datasets():
        changed = False
        for host in data.get("hosts", []):
            if _host_identifier(host) != host_id:
                continue
            vulns = host.get("vulnerabilities", [])
            kept = [v for v in vulns if v.get("id") != vuln_id]
            if len(kept) != len(vulns):
                host["vulnerabilities"] = kept
                changed = True
        if changed:
            _replace_dataset(dataset_id, data)
            _sync_cache()
            return True
    return False

def vulnerability_counts():
    counts = {sev: 0 for sev in VALID_SEVERITIES}
    total = 0
    for host in get_hosts():
        for vuln in host.get("vulnerabilities", []) or []:
            sev = vuln.get("severity")
            if sev in counts:
                counts[sev] += 1
            total += 1
    return counts, total