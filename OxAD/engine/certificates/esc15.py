from .common import finding, integer, published, subject_supplied


def run(templates, services):
    return [
        finding("ESC15", template, {"schema_version": integer(template.get("raw", {}).get("msPKI-Template-Schema-Version"))}, "potential")
        for template in templates
        if published(template, services)
        and integer(template.get("raw", {}).get("msPKI-Template-Schema-Version")) == 1
        and subject_supplied(template)
    ]
