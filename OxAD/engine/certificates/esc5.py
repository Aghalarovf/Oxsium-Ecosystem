from .common import finding, writable


def run(objects):
    return [
        finding("ESC5", item, {"write_sid": sid, "rights": rights})
        for item in objects
        for ok, sid, rights in [writable(item)]
        if ok
    ]
