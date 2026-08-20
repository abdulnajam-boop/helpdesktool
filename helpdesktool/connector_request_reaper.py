"""Recovers connector requests abandoned in ``pending_approval`` (Phase 8:
idempotency/loop prevention for the connector-request pipeline).

Unlike an ``Action`` (which an agent claims with a time-bound lease --
recovered by ``lease_reaper.py`` if the agent crashes mid-claim), a
``ConnectorRequest`` has no agent/claim step at all: it is created, then
waits on a human's ``POST /v1/connector-requests/{id}/decision``. Nothing
in the request path revisits a request no approver ever acted on -- it
would otherwise stay ``pending_approval`` forever, invisible except to
whoever remembers to look at the approvals queue. This worker finds
requests that have been ``pending_approval`` longer than
``Settings.connector_request_stale_after_hours`` and marks them
``expired`` with an audit event, so a human sees an explicit signal
instead of a request silently rotting. There is no retry/requeue path
here (unlike ``lease_reaper``'s bounded requeue) -- an expired approval
request is not something to blindly retry; a human who still wants it
done submits a new request through the normal flow, this time hopefully
decided before it goes stale again.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import SessionLocal, set_rls_bypass
from .db_models import ConnectorRequest
from .logging_config import configure_logging
from .persistence import SqlAuditLog, record_worker_heartbeat

LOG = logging.getLogger("helpdesktool-connector-request-reaper")


class ConnectorRequestReaper:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def process_batch(self, session: Session, limit: int = 50) -> int:
        # Stale requests can belong to any tenant and are not driven by
        # client input -- same narrow, documented exception as
        # lease_reaper/webhook_worker/retention_worker; see rls.py.
        set_rls_bypass(session, enabled=True)
        cutoff = datetime.now(UTC) - timedelta(
            hours=self.settings.connector_request_stale_after_hours
        )
        stale = session.scalars(
            select(ConnectorRequest)
            .where(
                ConnectorRequest.status == "pending_approval",
                ConnectorRequest.created_at < cutoff,
            )
            .order_by(ConnectorRequest.created_at)
            .limit(min(max(limit, 1), 100))
            .with_for_update(skip_locked=True)
        ).all()
        audit = SqlAuditLog(session)
        for request in stale:
            self._reap(audit, request)
        session.commit()
        set_rls_bypass(session, enabled=False)
        session.commit()
        return len(stale)

    def _reap(self, audit: SqlAuditLog, request: ConnectorRequest) -> None:
        request.status = "expired"
        request.decided_at = datetime.now(UTC)
        request.decision_reason = (
            "auto-expired: no approval decision within "
            f"{self.settings.connector_request_stale_after_hours} hours"
        )
        audit.append(
            tenant_id=request.tenant_id,
            correlation_id=request.id,
            event_type="connector_request.escalation_required",
            actor_id="system:connector_request_reaper",
            details={
                "status": request.status,
                "error": "connector request stayed pending_approval past the stale window",
                "operation": request.operation,
                "stale_after_hours": self.settings.connector_request_stale_after_hours,
            },
        )


def main() -> None:
    configure_logging()
    settings = get_settings()
    reaper = ConnectorRequestReaper(settings)
    while True:
        try:
            with SessionLocal() as session:
                processed = reaper.process_batch(session)
                record_worker_heartbeat(session, "connector_request_reaper", processed)
            if processed == 0:
                time.sleep(settings.connector_request_reaper_poll_seconds)
        except Exception:
            LOG.exception("connector request reaper batch failed")
            time.sleep(5)


if __name__ == "__main__":
    main()
