"""End-to-end smoke test for the full autonomous help-desk lifecycle.

Runs the whole documented loop through the real HTTP API, in as close to a
real production deployment as a test gets: PostgreSQL with row-level
security enforced via the actual restricted database role, OIDC-only human
authentication (no insecure headers, no development login), and a real
one-time enrollment token for device onboarding — tying together the
Milestone 2 (identity/RLS) and Milestone 3 (endpoint trust) work into one
proof that the whole stack still functions together end to end:

  tenant -> user -> device enrollment (one-time token)
  -> telemetry (low disk) -> deterministic incident detection
  -> incident correlated to a ticket ("diagnosis")
  -> operator proposes a remediation action ("remediation plan")
  -> policy evaluation (risk-based approval requirement)
  -> independent admin approval
  -> job dispatch -> agent claim -> agent execution -> verification
  -> ticket resolution (telemetry recovers) / incident resolved
  -> audit trail (hash-chained, queryable by correlation id)
  -> dashboard visibility (counts reflect everything above)

This does not replace the more targeted test files (test_oidc.py,
test_tenant_isolation_postgres.py, test_endpoint_trust.py,
test_lease_reaper.py, ...) — it exists to prove the pieces they each verify
in isolation actually compose into one working product.
"""

from __future__ import annotations

from helpdesktool.database import set_tenant_context
from helpdesktool.db_models import User
from tests.conftest import TEST_OIDC_AUDIENCE, TEST_OIDC_ISSUER
from tests.support import mint_token


def test_full_autonomous_helpdesk_lifecycle(postgres_client, oidc_test_keypair):
    http, factory = postgres_client
    private_key, _ = oidc_test_keypair

    def token_for(email: str) -> str:
        return mint_token(
            private_key,
            issuer=TEST_OIDC_ISSUER,
            audience=TEST_OIDC_AUDIENCE,
            subject=f"subject-{email}",
            email=email,
        )

    # --- tenant + user -------------------------------------------------
    bootstrap = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme IT", "admin_email": "owner@acme.example"},
    )
    assert bootstrap.status_code == 201, bootstrap.text
    tenant_id = bootstrap.json()["tenant_id"]
    owner_headers = {"Authorization": f"Bearer {token_for('owner@acme.example')}"}
    assert http.get("/v1/auth/me", headers=owner_headers).json()["role"] == "owner"

    # A second admin is required later for separation-of-duties approval.
    with factory() as session:
        set_tenant_context(session, tenant_id)
        session.add(User(tenant_id=tenant_id, email="admin@acme.example", role="admin"))
        session.commit()
    admin_headers = {"Authorization": f"Bearer {token_for('admin@acme.example')}"}

    # --- device enrollment via a one-time enrollment token -------------
    enrollment_token = http.post(
        "/v1/devices/enrollment-tokens",
        headers=owner_headers,
        json={"label": "smoke-test fleet"},
    )
    assert enrollment_token.status_code == 201
    raw_token = enrollment_token.json()["token"]

    enrolled = http.post(
        "/v1/devices/enroll-with-token",
        headers={"X-Enrollment-Token": raw_token},
        json={"external_id": "web-prod-01", "hostname": "web-prod-01", "os": "linux"},
    )
    assert enrolled.status_code == 201, enrolled.text
    device_id = enrolled.json()["device_id"]
    agent_headers = {"Authorization": f"Bearer {enrolled.json()['agent_token']}"}

    # --- telemetry: heartbeat + low-disk inventory ("observe") ---------
    heartbeat = http.post(
        f"/v1/devices/{device_id}/heartbeat",
        headers={**agent_headers, "Idempotency-Key": "hb-1"},
        json={"status": {"agent_version": "smoke-test"}},
    )
    assert heartbeat.status_code == 200

    low_disk_inventory = http.post(
        f"/v1/devices/{device_id}/inventory",
        headers={**agent_headers, "Idempotency-Key": "inv-1"},
        json={
            "collected_at": "2026-08-19T12:00:00Z",
            "payload": {
                "filesystems": [
                    {"mountpoint": "/", "total_bytes": 1000, "free_bytes": 30}
                ]
            },
        },
    )
    assert low_disk_inventory.status_code == 202
    incident_ids = low_disk_inventory.json()["incident_ids"]
    assert len(incident_ids) == 1
    incident_id = incident_ids[0]

    # --- detection -> incident + ticket ("diagnosis") -------------------
    incident = http.get(f"/v1/incidents/{incident_id}", headers=owner_headers).json()
    assert incident["status"] == "open"
    assert incident["severity"] in {"high", "critical"}
    assert incident["ticket"] is not None
    ticket_id = incident["ticket"]["id"]
    ticket = http.get(f"/v1/tickets/{ticket_id}", headers=owner_headers).json()
    assert ticket["status"] == "open"

    # --- remediation plan: operator proposes an approved skill ----------
    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "action-1"},
        json={
            "device_id": device_id,
            "ticket_id": ticket_id,
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    assert action.status_code == 201, action.text
    action_id = action.json()["id"]
    # --- policy evaluation: medium-risk skill requires approval ---------
    assert action.json()["status"] == "pending_approval"
    assert action.json()["risk"] == "medium"

    # A self-approval must be rejected (separation of duties)...
    self_approve = http.post(
        f"/v1/actions/{action_id}/decision",
        headers=owner_headers,
        json={"decision": "approve", "reason": "should be rejected"},
    )
    assert self_approve.status_code == 403
    # ...an independent admin can approve it.
    approved = http.post(
        f"/v1/actions/{action_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "within maintenance window"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "queued"

    # --- job dispatch -> agent claim -> execution -> verification -------
    jobs = http.get(f"/v1/devices/{device_id}/jobs", headers=agent_headers)
    assert [job["id"] for job in jobs.json()] == [action_id]

    claim = http.post(
        f"/v1/devices/{device_id}/jobs/{action_id}/claim",
        headers={**agent_headers, "Idempotency-Key": "claim-1"},
        json={},
    )
    assert claim.status_code == 200

    from linux_agent.executor import ServiceRestartExecutor

    class _FakeSystemctl:
        responses = iter(
            [
                "LoadState=loaded\nActiveState=active\nSubState=running\n",
                "",
                "LoadState=loaded\nActiveState=active\nSubState=running\n",
            ]
        )

        def __call__(self, command, *, timeout):
            import subprocess

            return subprocess.CompletedProcess(command, 0, next(self.responses), "")

    execution_result = ServiceRestartExecutor(
        ("demo.service",), runner=_FakeSystemctl()
    ).execute({"service": "demo.service"})
    assert execution_result["success"] is True

    result = http.post(
        f"/v1/devices/{device_id}/jobs/{action_id}/result",
        headers={
            **agent_headers,
            "Idempotency-Key": "result-1",
            "X-Claim-Token": claim.json()["claim_token"],
        },
        json=execution_result,
    )
    assert result.status_code == 200
    assert result.json()["status"] == "succeeded"

    action_detail = http.get(f"/v1/actions/{action_id}", headers=owner_headers).json()
    assert action_detail["execution_results"][0]["verified"] is True
    assert action_detail["execution_results"][0]["rollback_attempted"] is False

    # --- recovery: telemetry drops below threshold -> incident resolves -
    recovered_inventory = http.post(
        f"/v1/devices/{device_id}/inventory",
        headers={**agent_headers, "Idempotency-Key": "inv-2"},
        json={
            "collected_at": "2026-08-19T12:10:00Z",
            "payload": {
                "filesystems": [
                    {"mountpoint": "/", "total_bytes": 1000, "free_bytes": 600}
                ]
            },
        },
    )
    assert recovered_inventory.status_code == 202
    incident_after = http.get(
        f"/v1/incidents/{incident_id}", headers=owner_headers
    ).json()
    assert incident_after["status"] == "resolved"
    ticket_after = http.get(f"/v1/tickets/{ticket_id}", headers=owner_headers).json()
    assert ticket_after["status"] == "resolved"

    # --- audit trail: hash-chained, queryable by correlation id ---------
    incident_timeline = http.get(
        f"/v1/incidents/{incident_id}", headers=owner_headers
    ).json()["timeline"]
    incident_event_types = {event["event_type"] for event in incident_timeline}
    assert "incident.created" in incident_event_types
    assert "incident.resolved" in incident_event_types

    action_timeline = http.get(
        f"/v1/actions/{action_id}", headers=owner_headers
    ).json()["timeline"]
    action_event_types = {event["event_type"] for event in action_timeline}
    assert {
        "policy.evaluated",
        "action.approved",
        "execution.queued",
        "execution.claimed",
        "execution.reported",
        "execution.verified",
    }.issubset(action_event_types)

    full_audit = http.get("/v1/audit", headers=owner_headers)
    assert full_audit.status_code == 200
    assert {row["event_type"] for row in full_audit.json()} >= {
        "tenant.created",
        "device.enrolled",
        "ticket.created",
        "incident.created",
        "action.approved",
        "execution.reported",
        "incident.resolved",
        "ticket.resolved",
    }

    # --- dashboard visibility --------------------------------------------
    dashboard = http.get("/v1/dashboard", headers=owner_headers).json()
    assert dashboard["counts"]["devices"] == 1
    assert dashboard["counts"]["open_incidents"] == 0
    assert dashboard["counts"]["pending_approvals"] == 0
    assert any(row["id"] == action_id for row in dashboard["recent_actions"])
    assert any(row["id"] == ticket_id for row in dashboard["recent_tickets"])
    assert any(row["id"] == incident_id for row in dashboard["recent_incidents"])
