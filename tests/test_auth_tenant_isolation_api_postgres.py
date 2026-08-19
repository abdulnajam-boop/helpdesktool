"""End-to-end API tests for production authentication and tenant isolation.

Runs the FastAPI app in as close to real production mode as a test can:
PostgreSQL with row-level security enforced against the actual restricted
``helpdesk_app`` role, insecure header auth and development login both
disabled, and human authentication only via signed OIDC bearer tokens
verified against a real (test-keyed) JWKS-shaped verifier. See
``postgres_client`` in conftest.py.

``test_tenant_isolation_postgres.py`` proves the database-layer guarantee in
isolation; this file proves the same guarantee holds through the actual
HTTP surface an attacker would use, including the auth paths themselves.
"""

from __future__ import annotations

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


def _token(private_key, *, email: str, subject: str | None = None) -> str:
    return mint_token(
        private_key,
        issuer=TEST_OIDC_ISSUER,
        audience=TEST_OIDC_AUDIENCE,
        subject=subject or f"subject-{email}",
        email=email,
    )


def test_oidc_login_resolves_the_correct_tenant(postgres_client, oidc_test_keypair):
    http, _ = postgres_client
    private_key, _ = oidc_test_keypair
    identity = _bootstrap_tenant(http, "owner@tenant-a.example")

    response = http.get(
        "/v1/auth/me",
        headers={
            "Authorization": f"Bearer {_token(private_key, email='owner@tenant-a.example')}"
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tenant_id"] == identity["tenant_id"]
    assert body["role"] == "owner"


def test_unprovisioned_identity_is_rejected(postgres_client, oidc_test_keypair):
    http, _ = postgres_client
    private_key, _ = oidc_test_keypair
    _bootstrap_tenant(http, "owner@tenant-a.example")

    response = http.get(
        "/v1/auth/me",
        headers={
            "Authorization": f"Bearer {_token(private_key, email='nobody@nowhere.example')}"
        },
    )
    assert response.status_code == 403


def test_tampered_token_is_rejected(postgres_client, oidc_test_keypair):
    http, _ = postgres_client
    private_key, _ = oidc_test_keypair
    _bootstrap_tenant(http, "owner@tenant-a.example")
    token = _token(private_key, email="owner@tenant-a.example")
    header, payload, signature = token.split(".")
    tampered = (
        f"{header}.{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    )

    response = http.get("/v1/auth/me", headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401


def test_missing_bearer_token_is_rejected(postgres_client):
    http, _ = postgres_client
    response = http.get("/v1/auth/me")
    # No Authorization header at all and insecure header auth is disabled in
    # this (production-mode) fixture — pre-existing behavior for this exact
    # combination (see require_user), distinct from "a token was presented
    # and rejected" (401, covered by test_tampered_token_is_rejected).
    assert response.status_code == 503


def test_cross_tenant_device_read_is_denied(postgres_client, oidc_test_keypair):
    http, _ = postgres_client
    private_key, _ = oidc_test_keypair
    tenant_a = _bootstrap_tenant(http, "owner@tenant-a.example")
    tenant_b = _bootstrap_tenant(http, "owner@tenant-b.example")
    headers_a = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-a.example')}"
    }
    headers_b = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-b.example')}"
    }

    enrolled = http.post(
        "/v1/devices/enroll",
        headers=headers_b,
        json={"external_id": "b-server-1", "hostname": "b-server-1", "os": "linux"},
    )
    assert enrolled.status_code == 201, enrolled.text
    device_id = enrolled.json()["device_id"]

    # Tenant B can see its own device.
    assert http.get(f"/v1/devices/{device_id}", headers=headers_b).status_code == 200
    # Tenant A, authenticated as a real owner of a real (different) tenant,
    # gets a plain 404 for tenant B's device — not 403 (which would confirm
    # the device exists), not 200 (which would leak it).
    assert http.get(f"/v1/devices/{device_id}", headers=headers_a).status_code == 404
    # And it never shows up in tenant A's device list either.
    listing = http.get("/v1/devices", headers=headers_a)
    assert listing.status_code == 200
    assert all(row["id"] != device_id for row in listing.json())
    assert tenant_a["tenant_id"] != tenant_b["tenant_id"]


def test_cross_tenant_ticket_write_is_denied(postgres_client, oidc_test_keypair):
    http, _ = postgres_client
    private_key, _ = oidc_test_keypair
    _bootstrap_tenant(http, "owner@tenant-a.example")
    _bootstrap_tenant(http, "owner@tenant-b.example")
    headers_a = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-a.example')}"
    }
    headers_b = {
        "Authorization": f"Bearer {_token(private_key, email='owner@tenant-b.example')}"
    }

    ticket = http.post(
        "/v1/tickets", headers=headers_b, json={"title": "Tenant B's ticket"}
    )
    assert ticket.status_code == 201, ticket.text
    ticket_id = ticket.json()["id"]

    # Tenant A cannot even discover the ticket exists, let alone modify it.
    assert http.get(f"/v1/tickets/{ticket_id}", headers=headers_a).status_code == 404
    forged_update = http.patch(
        f"/v1/tickets/{ticket_id}", headers=headers_a, json={"status": "closed"}
    )
    assert forged_update.status_code == 404
    # And tenant B's ticket was not tampered with.
    still_open = http.get(f"/v1/tickets/{ticket_id}", headers=headers_b)
    assert still_open.json()["status"] == "open"


def test_ambiguous_email_requires_tenant_disambiguation(
    postgres_client, oidc_test_keypair
):
    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import User

    http, factory = postgres_client
    private_key, _ = oidc_test_keypair
    tenant_a = _bootstrap_tenant(http, "shared@example.com")
    tenant_b = _bootstrap_tenant(http, "unique-b@example.com")
    # Provision the same verified email into a second tenant too (e.g. a
    # contractor working with two customers) directly, since there is no
    # invitation flow yet — mirrors how existing tests create extra users.
    with factory() as session:
        set_tenant_context(session, tenant_b["tenant_id"])
        session.add(
            User(
                tenant_id=tenant_b["tenant_id"],
                email="shared@example.com",
                role="viewer",
            )
        )
        session.commit()

    token = _token(private_key, email="shared@example.com")

    unambiguous = http.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert unambiguous.status_code == 409

    resolved_a = http.get(
        "/v1/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": tenant_a["tenant_id"],
        },
    )
    assert resolved_a.status_code == 200
    assert resolved_a.json()["tenant_id"] == tenant_a["tenant_id"]
    assert resolved_a.json()["role"] == "owner"

    resolved_b = http.get(
        "/v1/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": tenant_b["tenant_id"],
        },
    )
    assert resolved_b.status_code == 200
    assert resolved_b.json()["role"] == "viewer"

    # A tenant this identity is genuinely not a member of is rejected, not
    # silently ignored/defaulted — the header can only ever narrow an
    # already-verified candidate set, never widen it.
    forged = http.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": str(uuid4())},
    )
    assert forged.status_code == 403


def test_role_enforcement_still_applies_through_oidc(
    postgres_client, oidc_test_keypair
):
    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import User

    http, factory = postgres_client
    private_key, _ = oidc_test_keypair
    tenant = _bootstrap_tenant(http, "owner@tenant.example")
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
    denied = http.post(
        "/v1/tickets", headers=viewer_headers, json={"title": "not allowed"}
    )
    assert denied.status_code == 403
    allowed_read = http.get("/v1/devices", headers=viewer_headers)
    assert allowed_read.status_code == 200


def test_insecure_header_auth_is_rejected_in_production_mode(postgres_client):
    http, _ = postgres_client
    response = http.get(
        "/v1/devices", headers={"X-Tenant-ID": "anything", "X-User-ID": "anything"}
    )
    assert response.status_code == 503
