from .common import finding, integer


EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000


def run(services):
    return [
        finding("ESC6", service, {"flags": integer(service.get("raw", {}).get("flags"))})
        for service in services
        if integer(service.get("raw", {}).get("flags")) & EDITF_ATTRIBUTESUBJECTALTNAME2
    ]
