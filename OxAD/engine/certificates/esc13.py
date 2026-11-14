from .common import finding, values


def run(templates, oids):
    linked = {str(value.get("raw", {}).get("msPKI-Cert-Template-OID")): value for value in oids}
    results = []
    for template in templates:
        policies = set(values(template.get("raw", {}).get("msPKI-Certificate-Application-Policy")))
        for policy in policies:
            oid = linked.get(str(policy))
            if oid and oid.get("raw", {}).get("msDS-OIDToGroupLink"):
                results.append(finding("ESC13", template, {"policy_oid": policy, "group_dn": oid["raw"]["msDS-OIDToGroupLink"]}))
    return results
