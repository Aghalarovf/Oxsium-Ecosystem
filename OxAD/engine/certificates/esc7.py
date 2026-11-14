from .common import finding, is_admin, values


def run(services):
    results = []
    for service in services:
        for ace in service.get("acl", []):
            sid = str(ace.get("principal_sid") or ace.get("sid") or "")
            rights = set(values(ace.get("rights") or ace.get("right")))
            if not is_admin(sid) and rights.intersection({"ManageCA", "ManageCertificates"}):
                results.append(finding("ESC7", service, {"principal_sid": sid, "rights": sorted(rights)}))
    return results
