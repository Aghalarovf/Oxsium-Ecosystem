def run(records):
    results = []
    for record in records:
        methods = record.get("certificate_mapping_methods")
        if methods is not None and int(methods) & 0x4:
            results.append({
                "rule": "ESC10",
                "severity": "high",
                "status": "potential",
                "target": record.get("dn") or record.get("name"),
                "detail": {"certificate_mapping_methods": methods},
            })
    return results
