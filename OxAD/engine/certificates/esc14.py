from .common import finding, values


def run(users):
    results = []
    for user in users:
        mappings = values(user.get("raw", {}).get("altSecurityIdentities"))
        weak = [value for value in mappings if "X509:<UPN>" in str(value).upper() or "X509:<RFC822>" in str(value).upper()]
        if weak:
            results.append(finding("ESC14", user, {"mappings": weak}, "potential"))
    return results
