from .common import ANY_PURPOSE, enrolled, finding, integer, manager_approval, oids, published


def run(templates, services):
    results = []
    for template in templates:
        if not published(template, services) or manager_approval(template):
            continue
        raw = template.get("raw", {})
        if oids(template) and ANY_PURPOSE not in oids(template):
            continue
        if integer(raw.get("msPKI-RA-Signature")):
            continue
        ok, sid, _ = enrolled(template)
        if ok:
            results.append(finding("ESC2", template, {"enroll_sid": sid}))
    return results
