from __future__ import annotations

import os
from pathlib import Path


class Config:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    OUTPUT_DIR = Path(os.getenv("OXAD_OUTPUT_DIR", str(PROJECT_ROOT / "output")))
    LDAP_PAGE_SIZE = int(os.getenv("OXAD_LDAP_PAGE_SIZE", 500))
    LDAP_CONNECT_TIMEOUT = int(os.getenv("OXAD_LDAP_TIMEOUT", 15))
    LDAP_RECEIVE_TIMEOUT = int(os.getenv("OXAD_LDAP_RECEIVE_TIMEOUT", 120))

    @classmethod
    def ensure_output_dir(cls) -> None:
        cls.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
