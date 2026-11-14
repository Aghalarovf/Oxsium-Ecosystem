import smtplib

from plugins.banner.base import BannerResult, failed, no, ok

SERVICE = "smtp"
PROTOCOL = "tcp"


def check(host: str, port: int, timeout_ms: int = 3000) -> BannerResult:
    timeout_s = timeout_ms / 1000.0
    smtp = None

    try:
        smtp = smtplib.SMTP(timeout=timeout_s)
        code, raw = smtp.connect(host, port)
        banner = raw.decode(errors="replace").strip() if isinstance(raw, bytes) else str(raw).strip()

        if not banner:
            return no(SERVICE, host, port, PROTOCOL, f"connected (code={code}) but server returned an empty banner")

        return ok(SERVICE, host, port, PROTOCOL, banner, f"[{code}] {banner}")
    except (smtplib.SMTPException, OSError) as exc:
        return failed(SERVICE, host, port, PROTOCOL, str(exc))
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass
