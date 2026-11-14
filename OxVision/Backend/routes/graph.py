from flask import request
from app import app
from helpers import _ok, _err
import store

OS_GROUP = {
    "Linux": "os-linux",
    "Windows": "os-windows",
    "Network": "os-network",
    "Virtual Machine": "os-virtualmachine",
    "Gateway": "os-gateway",
    "Firewall": "os-firewall",
    "Camera": "os-camera",
}

@app.route("/api/graph", methods=["GET"])
def get_graph():
    ds = store.get_dataset()
    if ds is None:
        return _err("No dataset loaded", 404)

    nodes = []
    edges = []

    host_ip_info = ds.get("host_ip") or {}
    scanner_id = "scanner"

    nodes.append({
        "id": scanner_id,
        "label": host_ip_info.get("ip") or "Unknown",
        "group": "scanner",
        "ip": host_ip_info.get("ip"),
        "interface": host_ip_info.get("interface"),
    })

    for h in store.query_hosts(request.args):
        host_id = f"host:{h.get('host')}"
        ports = h.get("ports", [])
        nodes.append({
            "id": host_id,
            "label": h.get("hostname") or h.get("host"),
            "ip": h.get("host"),
            "hostname": h.get("hostname", ""),
            "group": OS_GROUP.get(h.get("os"), "os-other"),
            "os": h.get("os"),
            "type": h.get("type"),
            "reason": h.get("reason"),
            "note": h.get("note", ""),
            "roles": h.get("roles") or [],
            "port_count": len(ports),
            "ports": ports,
        })
        edges.append({
            "from": scanner_id,
            "to": host_id,
            "type": h.get("type"),
        })

    return _ok(nodes=nodes, edges=edges)