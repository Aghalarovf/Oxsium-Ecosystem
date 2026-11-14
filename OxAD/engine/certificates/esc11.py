from .common import finding, integer


def run(services):
    return [
        finding("ESC11", service, {"interface_flags": integer(service.get("raw", {}).get("interfaceFlags"))}, "potential")
        for service in services
        if service.get("raw", {}).get("interfaceFlags") is not None
        and not integer(service.get("raw", {}).get("interfaceFlags")) & 0x200
    ]
