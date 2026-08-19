"""Bounded transactional-outbox delivery worker."""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import SessionLocal, set_rls_bypass
from .db_models import DomainEventRow, WebhookDelivery, WebhookSubscription
from .integrations import (
    EnvironmentSecretsProvider,
    IntegrationProvider,
    SignedWebhookProvider,
    canonical_payload,
    validate_webhook_url,
)
from .logging_config import configure_logging
from .persistence import record_worker_heartbeat

LOG = logging.getLogger("helpdesktool-webhook-worker")


class WebhookWorker:
    def __init__(
        self,
        provider: IntegrationProvider,
        settings: Settings,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.provider = provider
        self.settings = settings
        self.secrets = EnvironmentSecretsProvider(environment or dict(os.environ))

    def process_batch(self, session: Session, limit: int = 50) -> int:
        # This worker delivers pending webhooks across every tenant in one
        # batch by design (it is not driven by any per-request client input,
        # so there is no untrusted tenant_id in play here) — see
        # helpdesktool.rls for why this is the one place that sets this GUC.
        set_rls_bypass(session, enabled=True)
        now = datetime.now(UTC)
        deliveries = session.scalars(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.status == "pending",
                WebhookDelivery.next_attempt_at <= now,
            )
            .order_by(WebhookDelivery.next_attempt_at)
            .limit(min(max(limit, 1), 100))
            .with_for_update(skip_locked=True)
        ).all()
        for delivery in deliveries:
            self._deliver(session, delivery, now)
        session.commit()
        # Symmetric with the enable above: this session's underlying
        # connection is drawn from the same pool as API request sessions
        # (they are separate processes in the real deployment topology per
        # compose.yaml, but this keeps the invariant true even if that ever
        # changes, and in-process tests that reuse the same engine). Never
        # leave bypass=on on a connection once this batch is done with it.
        set_rls_bypass(session, enabled=False)
        session.commit()
        return len(deliveries)

    def _deliver(
        self, session: Session, delivery: WebhookDelivery, now: datetime
    ) -> None:
        subscription = session.get(WebhookSubscription, delivery.subscription_id)
        event = session.get(DomainEventRow, delivery.event_id)
        delivery.attempt_count += 1
        delivery.last_attempt_at = now
        if subscription is None or event is None or not subscription.active:
            delivery.status = "cancelled"
            delivery.last_error = "subscription or event unavailable"
            return
        try:
            validate_webhook_url(
                subscription.url, allow_http=self.settings.webhook_allow_http
            )
            secret = self.secrets.get(subscription.secret_ref)
            payload = canonical_payload(
                {
                    "id": event.id,
                    "tenant_id": event.tenant_id,
                    "type": event.event_type,
                    "subject_id": event.subject_id,
                    "occurred_at": event.occurred_at.isoformat(),
                    "schema_version": event.schema_version,
                    "data": event.data,
                }
            )
            response = self.provider.deliver(
                subscription.url,
                event.id,
                payload,
                secret,
                self.settings.webhook_timeout_seconds,
            )
            delivery.response_status = response.status_code
            if 200 <= response.status_code < 300:
                delivery.status = "delivered"
                delivery.delivered_at = now
                delivery.last_error = None
                return
            retryable = (
                response.status_code in {408, 425, 429} or response.status_code >= 500
            )
            self._fail(delivery, f"HTTP {response.status_code}", retryable, now)
        except Exception as exc:
            # Store only the exception class; URLs, secrets, and response bodies stay out of logs/DB.
            self._fail(delivery, type(exc).__name__, True, now)

    def _fail(
        self, delivery: WebhookDelivery, error: str, retryable: bool, now: datetime
    ) -> None:
        delivery.last_error = error[:200]
        if (
            not retryable
            or delivery.attempt_count >= self.settings.webhook_max_attempts
        ):
            delivery.status = "dead_letter"
            return
        delay = min(3600, 2 ** min(delivery.attempt_count, 11))
        delivery.next_attempt_at = now + timedelta(seconds=delay)


def main() -> None:
    configure_logging()
    worker = WebhookWorker(SignedWebhookProvider(), get_settings())
    while True:
        try:
            with SessionLocal() as session:
                processed = worker.process_batch(session)
                record_worker_heartbeat(session, "webhook_worker", processed)
            if processed == 0:
                time.sleep(2)
        except Exception:
            LOG.exception("webhook delivery batch failed")
            time.sleep(5)


if __name__ == "__main__":
    main()
