"""Prometheus-compatible observability: ``GET /metrics``.

Two kinds of metric live here, computed differently on purpose:

- **HTTP request metrics** (``helpdesk_http_requests_total``,
  ``helpdesk_http_request_duration_seconds``) are real-time counters/
  histograms, incremented by ``api.py``'s ``RequestIdMiddleware`` on every
  request as it happens — this is the only kind of metric where "since the
  process started" is the right semantics.
- **Business/domain metrics** (action/incident status counts, device
  online/offline, diagnosis fallback rate, webhook delivery outcomes,
  worker heartbeat age) are computed fresh from the database on every
  scrape, via plain aggregate ``COUNT(*) ... GROUP BY`` queries, rather than
  incremented at every call site throughout the codebase. This is
  deliberate: threading a counter increment into every state-transition
  code path risks silently missing one and drifting from reality, whereas a
  scrape-time aggregate query is always exactly consistent with what's
  actually in the database. At this MVP's scale, querying on every scrape
  (Prometheus's default interval is on the order of 15-30s) is cheap.

These aggregate queries need to see every tenant at once (a platform
operator's dashboard, not a per-tenant one) — see
``helpdesktool.auth.aggregating_platform_metrics`` for the narrowly scoped,
documented RLS bypass this requires, and ``helpdesktool.rls``'s module
docstring for why this is one of exactly three legitimate uses of that
mechanism. Nothing here ever returns or logs row-level tenant data, only
counts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import aggregating_platform_metrics
from .db_models import (
    Action,
    Device,
    Diagnosis,
    Incident,
    WebhookDelivery,
    WorkerHeartbeatRow,
)

# A device counts as "online" if it has heartbeat-ed within this window.
# Shared with api.py's device_json/dashboard so the API and this gauge never
# disagree about what "online" means.
DEVICE_ONLINE_THRESHOLD = timedelta(minutes=5)

REGISTRY = CollectorRegistry()

HTTP_REQUESTS_TOTAL = Counter(
    "helpdesk_http_requests_total",
    "Total HTTP requests handled",
    ["method", "path", "status"],
    registry=REGISTRY,
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "helpdesk_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
    registry=REGISTRY,
)

_ACTIONS_BY_STATUS = Gauge(
    "helpdesk_actions_total",
    "Actions by status, across every tenant",
    ["status"],
    registry=REGISTRY,
)
_INCIDENTS_BY_STATUS = Gauge(
    "helpdesk_incidents_total",
    "Incidents by status, across every tenant",
    ["status"],
    registry=REGISTRY,
)
_DEVICES_BY_ONLINE_STATUS = Gauge(
    "helpdesk_devices_total",
    "Devices by online/offline status, across every tenant",
    ["status"],
    registry=REGISTRY,
)
_DIAGNOSES_BY_FALLBACK = Gauge(
    "helpdesk_diagnoses_total",
    "AI diagnoses by whether the deterministic fallback was used, across every tenant",
    ["fallback_used"],
    registry=REGISTRY,
)
_WEBHOOK_DELIVERIES_BY_STATUS = Gauge(
    "helpdesk_webhook_deliveries_total",
    "Webhook deliveries by status, across every tenant",
    ["status"],
    registry=REGISTRY,
)
_WORKER_HEARTBEAT_AGE_SECONDS = Gauge(
    "helpdesk_worker_heartbeat_age_seconds",
    "Seconds since a background worker last completed a batch iteration",
    ["worker"],
    registry=REGISTRY,
)


def _refresh_business_metrics(session: Session) -> None:
    with aggregating_platform_metrics(session):
        _ACTIONS_BY_STATUS.clear()
        for status_value, count in session.execute(
            select(Action.status, func.count()).group_by(Action.status)
        ).all():
            _ACTIONS_BY_STATUS.labels(status=status_value).set(count)

        _INCIDENTS_BY_STATUS.clear()
        for status_value, count in session.execute(
            select(Incident.status, func.count()).group_by(Incident.status)
        ).all():
            _INCIDENTS_BY_STATUS.labels(status=status_value).set(count)

        online_cutoff = datetime.now(UTC) - DEVICE_ONLINE_THRESHOLD
        online_count = (
            session.scalar(
                select(func.count())
                .select_from(Device)
                .where(
                    Device.last_seen_at.is_not(None),
                    Device.last_seen_at >= online_cutoff,
                )
            )
            or 0
        )
        total_count = session.scalar(select(func.count()).select_from(Device)) or 0
        _DEVICES_BY_ONLINE_STATUS.clear()
        _DEVICES_BY_ONLINE_STATUS.labels(status="online").set(online_count)
        _DEVICES_BY_ONLINE_STATUS.labels(status="offline").set(
            total_count - online_count
        )

        _DIAGNOSES_BY_FALLBACK.clear()
        for fallback_used, count in session.execute(
            select(Diagnosis.fallback_used, func.count()).group_by(
                Diagnosis.fallback_used
            )
        ).all():
            _DIAGNOSES_BY_FALLBACK.labels(fallback_used=str(fallback_used).lower()).set(
                count
            )

        _WEBHOOK_DELIVERIES_BY_STATUS.clear()
        for status_value, count in session.execute(
            select(WebhookDelivery.status, func.count()).group_by(
                WebhookDelivery.status
            )
        ).all():
            _WEBHOOK_DELIVERIES_BY_STATUS.labels(status=status_value).set(count)

        _WORKER_HEARTBEAT_AGE_SECONDS.clear()
        now = datetime.now(UTC)
        for row in session.scalars(select(WorkerHeartbeatRow)).all():
            last = row.last_heartbeat_at
            if last.tzinfo is None:
                last = last.replace(tzinfo=UTC)
            _WORKER_HEARTBEAT_AGE_SECONDS.labels(worker=row.worker_name).set(
                (now - last).total_seconds()
            )


def render_metrics(session: Session) -> tuple[bytes, str]:
    """Refreshes the business-metric gauges from the database and returns
    the full Prometheus exposition-format body plus its content type.
    """
    _refresh_business_metrics(session)
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
