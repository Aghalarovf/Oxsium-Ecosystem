from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HttpEnumResult:
    host: str
    port: int
    scheme: str
    status_code: Optional[int] = None
    status_text: str = ""
    title: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    location: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def reachable(self) -> bool:
        return self.error is None


def ok(host: str, port: int, scheme: str, status_code: int, status_text: str,
       title: Optional[str], server: Optional[str], powered_by: Optional[str],
       location: Optional[str], headers: Dict[str, str], technologies: List[str]) -> HttpEnumResult:
    return HttpEnumResult(
        host=host,
        port=port,
        scheme=scheme,
        status_code=status_code,
        status_text=status_text,
        title=title,
        server=server,
        powered_by=powered_by,
        location=location,
        headers=headers,
        technologies=technologies,
    )


def failed(host: str, port: int, scheme: str, error: str) -> HttpEnumResult:
    return HttpEnumResult(host=host, port=port, scheme=scheme, error=error)
