def run(records):
    return [
        {
            "rule": "ESC12",
            "severity": "medium",
            "status": "potential",
            "target": record.get("dn") or record.get("name"),
            "detail": {"probe_required": True},
        }
        for record in records
        if record.get("record_type") == "enrollment_service"
        and record.get("raw", {}).get("private_key_storage_probe")
    ]
