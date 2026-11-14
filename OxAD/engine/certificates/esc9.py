from .common import finding, integer, published


def run(templates, services):
    return [
        finding("ESC9", template, {"enrollment_flags": integer(template.get("raw", {}).get("msPKI-Enrollment-Flag"))})
        for template in templates
        if published(template, services)
        and integer(template.get("raw", {}).get("msPKI-Enrollment-Flag")) & 0x80000
    ]
