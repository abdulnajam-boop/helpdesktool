from helpdesktool.events import DomainEvent, EventType, sanitize_event_data


def test_domain_event_has_stable_versioned_envelope():
    event = DomainEvent.create(
        "tenant", EventType.TICKET_CREATED, "ticket", {"priority": "high"}
    )
    envelope = event.envelope()
    assert envelope["type"] == "ticket.created"
    assert envelope["tenant_id"] == "tenant"
    assert envelope["schema_version"] == 1
    assert envelope["data"] == {"priority": "high"}


def test_event_sanitizer_redacts_nested_secrets():
    sanitized = sanitize_event_data(
        {
            "token": "top-secret",
            "nested": {"password": "bad", "safe": "ok"},
            "items": [{"authorization": "Bearer secret"}],
        }
    )
    assert sanitized == {
        "token": "[REDACTED]",
        "nested": {"password": "[REDACTED]", "safe": "ok"},
        "items": [{"authorization": "[REDACTED]"}],
    }
