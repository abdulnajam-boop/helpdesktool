"""Regression checks keeping additive job/outbox migrations aligned with the ORM."""

from pathlib import Path

from helpdesktool.db_models import (
    Action,
    DomainEventRow,
    ExecutionResultRow,
    WebhookDelivery,
    WebhookSubscription,
)


def column_names(model) -> set[str]:
    return set(model.__table__.columns.keys())


def test_agent_job_migration_columns_exist_in_orm():
    assert {
        "claim_token_hash",
        "claimed_at",
        "lease_expires_at",
        "attempt",
    } <= column_names(Action)
    assert {"verified", "rollback_attempted", "rollback_succeeded"} <= column_names(
        ExecutionResultRow
    )


def test_webhook_outbox_models_match_migration_tables():
    assert DomainEventRow.__tablename__ == "domain_events"
    assert WebhookSubscription.__tablename__ == "webhook_subscriptions"
    assert WebhookDelivery.__tablename__ == "webhook_deliveries"
    migration = Path("migrations/versions/0003_domain_events_webhooks.py").read_text()
    for table in (DomainEventRow, WebhookSubscription, WebhookDelivery):
        assert f'"{table.__tablename__}"' in migration
