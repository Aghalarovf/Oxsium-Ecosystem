from .common import enrolled, finding, manager_approval, published, writable


def run(templates, services):
    results = []
    for template in templates:
        writable_template, sid, rights = writable(template)
        if not writable_template or not published(template, services):
            continue
        enrolled_template, enroll_sid, _ = enrolled(template)
        if enrolled_template and not manager_approval(template):
            results.append(finding("ESC4", template, {"write_sid": sid, "rights": rights, "enroll_sid": enroll_sid}))
    return results
