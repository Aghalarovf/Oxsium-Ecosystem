from .common import AUTH_EKUS, REQUEST_AGENT, enrolled, finding, integer, manager_approval, published, oids, values


def _raw(template):
    return template.get("raw", {})


def _schema_version(template):
    return integer(_raw(template).get("msPKI-Template-Schema-Version"), 1)


def _ra_signatures(template):
    return integer(_raw(template).get("msPKI-RA-Signature"))


def _ra_policies(template):
    return {str(v) for v in values(_raw(template).get("msPKI-RA-Application-Policies"))}


def _is_agent_template(template):
    return REQUEST_AGENT in oids(template) and _ra_signatures(template) == 0


def _is_target_template(template):
    eku = oids(template)
    if eku and not eku & AUTH_EKUS:
        return False
    if _schema_version(template) == 1:
        return True
    return _ra_signatures(template) >= 1 and REQUEST_AGENT in _ra_policies(template)


def run(templates, services):
    results = []
    for template in templates:
        if not published(template, services) or manager_approval(template):
            continue
        ok, sid, rights = enrolled(template)
        if not ok:
            continue
        if _is_agent_template(template):
            results.append(
                finding(
                    "ESC3",
                    template,
                    {
                        "role": "enrollment_agent",
                        "enroll_sid": sid,
                        "enroll_rights": rights,
                        "description": "Template allows the enrollee to request a Certificate Request Agent certificate, which can sign on-behalf-of requests against any vulnerable target template.",
                    },
                )
            )
        if _is_target_template(template):
            results.append(
                finding(
                    "ESC3",
                    template,
                    {
                        "role": "target",
                        "enroll_sid": sid,
                        "enroll_rights": rights,
                        "schema_version": _schema_version(template),
                        "ra_signatures_required": _ra_signatures(template),
                        "description": "Template accepts an on-behalf-of enrollment request signed by a Certificate Request Agent certificate and can issue for an arbitrary subject.",
                    },
                )
            )
    return results