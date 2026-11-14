from __future__ import annotations

import logging
import threading

from core.session import Session
from modules.base import BaseModule

from .api import get_domain_acls
from .models import AclFilterConfig, ObjectScope

logger = logging.getLogger(__name__)


class AclResult(list):
    def __init__(self, records=(), result: dict | None = None):
        super().__init__(records)
        self.result = result


class AcesModule(BaseModule):
    name = "aces"

    def run(self, session: Session) -> AclResult:
        stream_lock = threading.Lock()
        streamed: list[dict] = []

        def _acl_stream_write(records: list[dict]) -> None:
            with stream_lock:
                streamed.extend(records)

        acl_result = get_domain_acls(
            session,
            acl_filter=AclFilterConfig(),
            scope=ObjectScope.ALL_WITH_ACL,
            on_records=_acl_stream_write,
        )

        if acl_result.get("success"):
            acl_result.setdefault("meta", {})
            acl_result["meta"]["shared_session"] = True
            return AclResult(acl_result["acls"], acl_result)

        if streamed:
            final_result = {
                **acl_result,
                "acls": streamed,
                "count": len(streamed),
            }
            return AclResult(streamed, final_result)

        logger.warning("acl collector failed: %s", acl_result.get("error"))
        return AclResult([], None)