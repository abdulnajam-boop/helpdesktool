"""API-level tests for POST /v1/incidents/{id}/diagnose against real
PostgreSQL with RLS and OIDC enforced (see ``postgres_client`` in
conftest.py) — proves the AI diagnosis endpoint respects the same tenant
isolation and role enforcement as every other write path, and that no AI
provider configuration is required for it to work (deterministic fallback).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from tests.conftest import TEST_OIDC_AUDIENCE, TEST_OIDC_ISSUER
from tests.support import mint_token


def _bootstrap_tenant(http, admin_email: str) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": f"Tenant {uuid4()}", "admin_email": admin_email},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _token(private_key, *, email: str) -> str:
    return mint_token(
        private_key,
        issuer=TEST_OIDC_ISSUER,
        audience=TEST_OIDC_AUDIENCE,
        subject=f"subject-{email}",
        email=email,
    )


def _enroll_device(http, headers: dict) -> str:
    response = http.post(
        "/v1/devices/enroll",
        headers=headers,
        json={"external_id": "device-1", "hostname": "device-1", "os": "linux"},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["device_id"])


def _seed_incident(factory, *, tenant_id: str, device_id: str) -> str:
    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import Incident

    now = datetime.now(UTC)
    with factory() as session:
        set_tenant_context(session, tenant_id)
        incident = Incident(
            tenant_id=tenant_id,
            device_id=device_id,
            incident_type="low_disk_space",
            severity="critical",
            status="open",
            summary="Disk usage above threshold",
            evidence={"free_percent": 3.0},
            correlation_key="low_disk_space:/",
            occurrence_count=2,
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(incident)
        session.commit()
        return str(incident.id)


def test_diagnose_incident_persists_and_returns_a_fallback_result_by_default(
    postgres_client, oidc_test_keypair
):
    http, factory = postgres_client
    private_key, _ = oidc_test_keypair
    tenant = _bootstrap_tenant(http, "owner@tenant-a.example")
    headers = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-a.example')}"
    }
    device_id = _enroll_device(http, headers)
    incident_id = _seed_incident(
        factory, tenant_id=tenant["tenant_id"], device_id=device_id
    )

    response = http.post(f"/v1/incidents/{incident_id}/diagnose", headers=headers)
    assert response.status_code == 201, response.text
    body = response.json()
    # No AI provider is configured in tests by default, so get_ai_provider
    # selects DeterministicFallbackProvider as the primary provider itself;
    # it never raises, so fallback_used (which only flags "a *configured*
    # provider failed and we fell back") stays False here.
    assert body["fallback_used"] is False
    assert body["provider_name"] == "deterministic-fallback"
    assert body["incident_id"] == incident_id
    assert "critical" in body["summary"]
    assert body["escalate"] is True

    detail = http.get(f"/v1/incidents/{incident_id}", headers=headers)
    assert detail.status_code == 200
    diagnoses = detail.json()["diagnoses"]
    assert len(diagnoses) == 1
    assert diagnoses[0]["id"] == body["id"]


def test_cross_tenant_diagnose_is_denied(postgres_client, oidc_test_keypair):
    http, factory = postgres_client
    private_key, _ = oidc_test_keypair
    tenant_a = _bootstrap_tenant(http, "owner@tenant-a.example")
    tenant_b = _bootstrap_tenant(http, "owner@tenant-b.example")
    headers_a = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-a.example')}"
    }
    headers_b = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-b.example')}"
    }
    device_id = _enroll_device(http, headers_b)
    incident_id = _seed_incident(
        factory, tenant_id=tenant_b["tenant_id"], device_id=device_id
    )

    forged = http.post(f"/v1/incidents/{incident_id}/diagnose", headers=headers_a)
    assert forged.status_code == 404
    assert tenant_a["tenant_id"] != tenant_b["tenant_id"]

    # And tenant B's own diagnosis still succeeds normally.
    genuine = http.post(f"/v1/incidents/{incident_id}/diagnose", headers=headers_b)
    assert genuine.status_code == 201


def test_diagnose_requires_operator_role_or_above(postgres_client, oidc_test_keypair):
    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import User

    http, factory = postgres_client
    private_key, _ = oidc_test_keypair
    tenant = _bootstrap_tenant(http, "owner@tenant.example")
    owner_headers = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant.example')}"
    }
    with factory() as session:
        set_tenant_context(session, tenant["tenant_id"])
        session.add(
            User(
                tenant_id=tenant["tenant_id"],
                email="viewer@tenant.example",
                role="viewer",
            )
        )
        session.commit()
    viewer_headers = {
        "Authorization": f"Bearer {_token(private_key, email='viewer@tenant.example')}"
    }
    device_id = _enroll_device(http, owner_headers)
    incident_id = _seed_incident(
        factory, tenant_id=tenant["tenant_id"], device_id=device_id
    )

    denied = http.post(f"/v1/incidents/{incident_id}/diagnose", headers=viewer_headers)
    assert denied.status_code == 403
