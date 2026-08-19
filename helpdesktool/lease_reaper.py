"""Recovers action jobs abandoned by a crashed or disconnected agent.

``claim_job`` in api.py leases a job to a device for 60 seconds. If the
agent crashes, loses network, or is killed between claiming and reporting a
result, nothing else in the request path ever revisits that job — it would
otherwise stay ``claimed`` forever, invisible to ``poll_jobs`` (which only
returns ``queued`` actions) and to any operator. This worker finds exactly
those abandoned claims and either returns them to the queue (bounded by
``lease_reaper_max_attempts``, reusing the same ``attempt`` counter
``claim_job`` already increments) or marks them failed with an
``action.escalation_required`` audit event once retries are exhausted, so a
human sees it instead of a job vanishing silently.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import SessionLocal, set_rls_bypass
from .db_models import Action
from .persistence import SqlAuditLog

LOG = logging.getLogger("helpdesktool-lease-reaper")


class LeaseReaper:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def process_batch(self, session: Session, limit: int = 50) -> int:
        # Abandoned claims can belong to any tenant and are not driven by
        # client input — see helpdesktool.rls for why this is one of the two
        # places that legitimately sets this GUC (the other is the webhook
        # delivery worker).
        set_rls_bypass(session, enabled=True)
        now = datetime.now(UTC)
        expired = session.scalars(
            select(Action)
            .where(
                Action.status == "claimed",
                Action.lease_expires_at.is_not(None),
                Action.lease_expires_at < now,
            )
            .order_by(Action.claimed_at)
            .limit(min(max(limit, 1), 100))
            .with_for_update(skip_locked=True)
        ).all()
        audit = SqlAuditLog(session)
        for action in expired:
            self._reap(audit, action, now)
        session.commit()
        set_rls_bypass(session, enabled=False)
        session.commit()
        return len(expired)

    def _reap(self, audit: SqlAuditLog, action: Action, now: datetime) -> None:
        previous_status = action.status
        action.claim_token_hash = None
        action.claimed_at = None
        action.lease_expires_at = None
        if action.attempt >= self.settings.lease_reaper_max_attempts:
            action.status = "failed"
            audit.append(
                tenant_id=action.tenant_id,
                correlation_id=action.id,
                event_type="action.escalation_required",
                actor_id="system:lease_reaper",
                details={
                    "status": action.status,
                    "error": "job lease expired and retry attempts were exhausted",
                    "attempt": action.attempt,
                    "previous_status": previous_status,
                },
            )
            return
        action.status = "queued"
        audit.append(
            tenant_id=action.tenant_id,
            correlation_id=action.id,
            event_type="execution.lease_expired_requeued",
            actor_id="system:lease_reaper",
            details={
                "attempt": action.attempt,
                "previous_status": previous_status,
                "new_status": action.status,
            },
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    settings = get_settings()
    reaper = LeaseReaper(settings)
    while True:
        try:
            with SessionLocal() as session:
                processed = reaper.process_batch(session)
            if processed == 0:
                time.sleep(settings.lease_reaper_poll_seconds)
        except Exception:
            LOG.exception("lease reaper batch failed")
            time.sleep(5)


if __name__ == "__main__":
    main()
