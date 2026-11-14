from flask import request
from app import app
from helpers import _ok, _err
import store

@app.route("/api/meta", methods=["GET"])
def get_meta():
    ds = store.get_dataset()
    if ds is None:
        return _err("No dataset loaded", 404)
    subnet = request.args.get("subnet")
    subnet_group = request.args.get("subnet_group")
    return _ok(
        mode=ds.get("mode"),
        threads=ds.get("threads"),
        subnets=store.get_subnets(),
        subnet_counts=store.subnet_host_counts(),
        subnet_names=store.get_subnet_names(),
        subnet_groups=store.get_subnet_groups(),
        subnet_group_names=sorted(set(store.get_subnet_group_names()) | set(store.get_subnet_groups().values()), key=str.lower),
        host_count=len(store.query_hosts(request.args)),
        total_hosts=len(store.get_hosts(subnet, subnet_group)),
        default_roles=store.DEFAULT_ROLES,
        options=store.filter_options(subnet, subnet_group),
    )

@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    ds = store.get_dataset()
    if ds is None:
        return _err("No dataset loaded", 404)
    source = store.query_hosts(request.args)
    subnets = store.host_subnets(source)
    hosts = []
    for h, subnet in zip(source, subnets):
        hosts.append({
            "host": h.get("host"),
            "hostname": h.get("hostname", ""),
            "os": h.get("os"),
            "type": h.get("type"),
            "reason": h.get("reason"),
            "note": h.get("note", ""),
            "roles": h.get("roles") or [],
            "subnet": subnet,
            "port_count": len(h.get("ports", [])),
            "ports": h.get("ports", []),
        })
    return _ok(
        hosts=hosts,
        total=len(hosts),
        unfiltered_total=len(store.get_hosts(request.args.get("subnet"), request.args.get("subnet_group"))),
    )

@app.route("/api/ports", methods=["GET"])
def get_ports():
    ds = store.get_dataset()
    if ds is None:
        return _err("No dataset loaded", 404)
    counter = {}
    for h in store.query_hosts(request.args):
        for p in h.get("ports", []):
            key = f"{p.get('port')}/{p.get('protocol')}"
            if key not in counter:
                counter[key] = {
                    "port": p.get("port"),
                    "protocol": p.get("protocol"),
                    "service": p.get("service"),
                    "count": 0,
                    "hosts": [],
                }
            counter[key]["count"] += 1
            counter[key]["hosts"].append(h.get("host"))
    ports = sorted(counter.values(), key=lambda x: -x["count"])
    return _ok(ports=ports, total=len(ports))