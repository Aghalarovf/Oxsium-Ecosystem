import ftplib

from plugins.banner.base import BannerResult, failed, no, ok

SERVICE = "ftp"
PROTOCOL = "tcp"


def check(host: str, port: int, timeout_ms: int = 3000) -> BannerResult:
    timeout_s = timeout_ms / 1000.0
    ftp = ftplib.FTP(timeout=timeout_s)

    try:
        ftp.connect(host, port, timeout=timeout_s)
        banner = (ftp.getwelcome() or "").strip()

        if not banner:
            return no(SERVICE, host, port, PROTOCOL, "connected but server returned an empty banner")

        return ok(SERVICE, host, port, PROTOCOL, banner)
    except (*ftplib.all_errors, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        try:
            ftp.close()
        except Exception:
            pass
