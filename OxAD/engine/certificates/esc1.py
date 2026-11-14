from .common import AUTH_EKUS, enrolled, finding, integer, manager_approval, oids, published, subject_supplied


def run(templates, services):
    results = []
    for template in templates:
        if not published(template, services) or not subject_supplied(template) or manager_approval(template):
            continue
        eku = oids(template)
        if eku and not eku & AUTH_EKUS:
            continue
        if integer(template.get("raw", {}).get("msPKI-RA-Signature")):
            continue
        ok, sid, _ = enrolled(template)
        if ok:
            results.append(finding("ESC1", template, {"enroll_sid": sid}))
    return results