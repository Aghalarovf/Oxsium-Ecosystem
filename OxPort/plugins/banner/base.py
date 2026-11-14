from dataclasses import dataclass
from typing import Optional


@dataclass
class BannerResult:
    service: str
    host: str
    port: int
    protocol: str
    banner: Optional[str]
    detail: str
    error: Optional[str] = None

    @property
    def grabbed(self) -> bool:
        return self.banner is not None and self.error is None


def ok(service: str, host: str, port: int, protocol: str, banner: str, detail: str = "") -> BannerResult:
    return BannerResult(
        service=service, host=host, port=port, protocol=protocol,
        banner=banner, detail=detail or banner,
    )


def no(service: str, host: str, port: int, protocol: str, detail: str) -> BannerResult:
    return BannerResult(
        service=service, host=host, port=port, protocol=protocol,
        banner=None, detail=detail,
    )


def failed(service: str, host: str, port: int, protocol: str, error: str) -> BannerResult:
    return BannerResult(
        service=service, host=host, port=port, protocol=protocol,
        banner=None, detail="banner grab failed", error=error,
    )
