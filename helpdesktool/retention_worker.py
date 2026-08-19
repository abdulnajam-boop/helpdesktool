"""Bounded data-retention cleanup: heartbeats, device inventory snapshots,
and expired idempotency records.

Trust model
-----------
Like ``webhook_worker``/``lease_reaper``, this is a trusted, scheduled,
non-request-driven process that legitimately operates across every tenant
by design (retention policy is platform-wide, not something any one
tenant's request context could scope), so it is the fourth and last
documented use of the cross-tenant ``rls_bypass`` GUC — see
``helpdesktool.rls``'s module docstring, kept in sync with this.

**Audit events (`audit_events`) are deliberately never touched here.** They
are hash-chained (``helpdesktool/audit.py``) — deleting an old row would
break verification of every row after it, since each row's
``previous_hash`` is only meaningful if the row it points to still exists
and still matches. A real retention story for audit data needs a
checkpoint/archival design (periodically anchor a new chain "genesis" from
a signed snapshot of the segment being archived, so verification can
resume from the checkpoint forward) that this pass did not build. Until
that exists, audit history is retained indefinitely **by design**, not by
oversight — silently deleting old audit rows to "clean up" would be
exactly the kind of "weaken existing protections to make something easier"
this codebase's engineering discipline explicitly rejects.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import SessionLocal, set_rls_bypass
from .db_models import DeviceInventory, Heartbeat, IdempotencyRecord
from .logging_config import configure_logging
from .persistence import record_worker_heartbeat

LOG = logging.getLogger("helpdesktool-retention-worker")


class RetentionWorker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def process_batch(self, session: Session) -> int:
        set_rls_bypass(session, enabled=True)
        now = datetime.now(UTC)
        deleted = 0
        deleted += self._purge(
            session,
            Heartbeat,
            Heartbeat.received_at,
            now - timedelta(days=self.settings.heartbeat_retention_days),
        )
        deleted += self._purge(
            session,
            DeviceInventory,
            DeviceInventory.collected_at,
            now - timedelta(days=self.settings.inventory_retention_days),
        )
        deleted += self._purge(
            session,
            IdempotencyRecord,
            IdempotencyRecord.created_at,
            now - timedelta(days=self.settings.idempotency_record_retention_days),
        )
        session.commit()
        set_rls_bypass(session, enabled=False)
        session.commit()
        return deleted

    @staticmethod
    def _purge(session: Session, model: Any, column: Any, cutoff: datetime) -> int:
        result = cast(
            CursorResult[Any], session.execute(delete(model).where(column < cutoff))
        )
        return result.rowcount


def main() -> None:
    configure_logging()
    settings = get_settings()
    worker = RetentionWorker(settings)
    while True:
        try:
            with SessionLocal() as session:
                deleted = worker.process_batch(session)
                record_worker_heartbeat(session, "retention_worker", deleted)
            if deleted:
                LOG.info("retention worker purged %d expired row(s)", deleted)
        except Exception:
            LOG.exception("retention worker batch failed")
        time.sleep(settings.retention_worker_poll_seconds)


if __name__ == "__main__":
    main()
