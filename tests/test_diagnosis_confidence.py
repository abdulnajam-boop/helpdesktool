"""Proves POST /v1/incidents/{id}/diagnose never trusts a provider's own
confidence claim (Phase 5) -- even a provider that isn't
OpenAICompatibleProvider (which already discards it at parse time, see
tests/test_ai_provider.py) cannot influence the persisted/returned
confidence, because api.py's diagnose_incident always overwrites it with
helpdesktool.confidence's deterministic score before persisting.
"""

from __future__ import annotations

from datetime import UTC, datetime


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


class _OverconfidentFakeProvider:
    """A deliberately malicious/broken provider claiming maximum
    confidence for everything, regardless of evidence quality -- exactly
    the failure mode Phase 5 exists to make impossible to act on.
    """

    name = "overconfident-fake"
    model = "fake"

    def diagnose(self, evidence):
        from helpdesktool.ai.provider import DiagnosisProposal

        return DiagnosisProposal(
            summary="Definitely a critical compromise, trust me.",
            likely_root_cause="Definitely malware.",
            confidence=0.99,
            suggested_skill_id=None,
            escalate=True,
            escalation_reason="I said so.",
        )


def test_diagnose_incident_ignores_a_providers_claimed_confidence(client, monkeypatch):
    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "d1", "hostname": "d1", "os": "linux"},
    )
    device_id = enrolled.json()["device_id"]

    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import Incident

    now = datetime.now(UTC)
    with factory() as session:
        set_tenant_context(session, identity["tenant_id"])
        incident = Incident(
            tenant_id=identity["tenant_id"],
            device_id=device_id,
            incident_type="low_disk_space",
            severity="low",
            status="open",
            summary="Disk usage above threshold",
            evidence={"free_percent": 20.0},
            correlation_key="low_disk_space:/",
            occurrence_count=1,
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(incident)
        session.commit()
        incident_id = incident.id

    monkeypatch.setattr(
        "helpdesktool.api.get_ai_provider",
        lambda **kwargs: _OverconfidentFakeProvider(),
    )
    response = http.post(f"/v1/incidents/{incident_id}/diagnose", headers=owner_headers)
    assert response.status_code == 201, response.text
    body = response.json()
    # The fake provider claimed 0.99; a single, non-recurring, low-severity
    # incident cannot deterministically earn anywhere near that -- proving
    # the claimed value was discarded and replaced, not merely capped.
    assert body["confidence"] != 0.99
    assert body["confidence"] < 0.9
    assert body["summary"] == "Definitely a critical compromise, trust me."
