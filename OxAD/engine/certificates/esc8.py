from .common import finding, values


def run(services):
    return [
        finding("ESC8", service, {"host": service.get("raw", {}).get("dNSHostName"), "probe_required": True}, "potential")
        for service in services
        if service.get("raw", {}).get("dNSHostName")
        and any(str(value).lower() in {"http", "https"} for value in values(service.get("raw", {}).get("msPKI-Enrollment-Servers")))
    ]
