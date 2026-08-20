"""Tests for GET /v1/reports/summary and helpdesktool.reporting.build_report."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from linux_agent.executor import ServiceRestartExecutor


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enroll_device(http, owner_headers) -> dict:
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "agent-1", "hostname": "server-1", "os": "linux"},
    )
    assert enrolled.status_code == 201, enrolled.text
    return enrolled.json()


def test_report_reflects_remediation_and_approval_activity(client):
    from helpdesktool.db_models import User

    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = _enroll_device(http, owner_headers)

    ticket = http.post(
        "/v1/tickets",
        headers=owner_headers,
        json={"title": "Restart web service", "device_id": device["device_id"]},
    )
    assert ticket.status_code == 201
    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "action-1"},
        json={
            "device_id": device["device_id"],
            "ticket_id": ticket.json()["id"],
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    assert action.status_code == 201
    assert action.json()["status"] == "pending_approval"

    with factory() as session:
        approver = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(approver)
        session.commit()
        approver_id = approver.id
    approved = http.post(
        f"/v1/actions/{action.json()['id']}/decision",
        headers={"X-Tenant-ID": identity["tenant_id"], "X-User-ID": approver_id},
        json={"decision": "approve", "reason": "maintenance window"},
    )
    assert approved.status_code == 200

    claim = http.post(
        f"/v1/devices/{device['device_id']}/jobs/{action.json()['id']}/claim",
        headers={
            "Authorization": f"Bearer {device['agent_token']}",
            "Idempotency-Key": "claim-1",
        },
        json={},
    )
    assert claim.status_code == 200

    class Runner:
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

    execution = ServiceRestartExecutor(("demo.service",), runner=Runner()).execute(
        {"service": "demo.service"}
    )
    result = http.post(
        f"/v1/devices/{device['device_id']}/jobs/{action.json()['id']}/result",
        headers={
            "Authorization": f"Bearer {device['agent_token']}",
            "Idempotency-Key": "result-1",
            "X-Claim-Token": claim.json()["claim_token"],
        },
        json=execution,
    )
    assert result.json()["status"] == "succeeded"

    report = http.get("/v1/reports/summary", headers=owner_headers)
    assert report.status_code == 200
    body = report.json()
    assert body["remediation"]["attempts"] == 1
    assert body["remediation"]["succeeded"] == 1
    assert body["remediation"]["failed"] == 0
    assert body["remediation"]["success_rate"] == 1.0
    assert body["approvals"]["approved"] == 1
    assert body["approvals"]["denied"] == 0
    assert body["approvals"]["avg_time_to_decision_seconds"] is not None
    assert body["tickets"]["opened"] == 1
    assert body["devices"]["total"] == 1
    assert body["security"] == {"policy_denials": 0, "approval_denials": 0}


def test_report_distinguishes_policy_denial_from_approval_denial(client):
    from helpdesktool.db_models import User

    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = _enroll_device(http, owner_headers)

    # Policy-denied outright: never reaches the approval step, so there is
    # no matching Approval row -- this is the case build_report's anti-join
    # must isolate from an operator denial.
    policy_denied = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "policy-denied-1"},
        json={
            "device_id": device["device_id"],
            "skill_id": "totally.unregistered.skill",
            "parameters": {},
        },
    )
    assert policy_denied.status_code == 201
    assert policy_denied.json()["status"] == "denied"

    # Operator-denied: goes through pending_approval, then an admin
    # explicitly rejects it, which does create an Approval row.
    pending = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "operator-denied-1"},
        json={
            "device_id": device["device_id"],
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    assert pending.status_code == 201
    assert pending.json()["status"] == "pending_approval"
    with factory() as session:
        approver = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(approver)
        session.commit()
        approver_id = approver.id
    denied = http.post(
        f"/v1/actions/{pending.json()['id']}/decision",
        headers={"X-Tenant-ID": identity["tenant_id"], "X-User-ID": approver_id},
        json={"decision": "deny", "reason": "not now"},
    )
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"

    report = http.get("/v1/reports/summary", headers=owner_headers)
    assert report.status_code == 200
    assert report.json()["security"] == {"policy_denials": 1, "approval_denials": 1}


def test_report_default_period_is_trailing_seven_days(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    report = http.get("/v1/reports/summary", headers=owner_headers)
    assert report.status_code == 200
    period = report.json()["period"]
    start = datetime.fromisoformat(period["start"])
    end = datetime.fromisoformat(period["end"])
    assert abs((end - start) - timedelta(days=7)) < timedelta(seconds=5)


def test_report_accepts_explicit_period(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    start = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    end = datetime.now(UTC).isoformat()
    report = http.get(
        "/v1/reports/summary",
        params={"start": start, "end": end},
        headers=owner_headers,
    )
    assert report.status_code == 200


def test_report_rejects_end_before_start(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    start = datetime.now(UTC).isoformat()
    end = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    report = http.get(
        "/v1/reports/summary",
        params={"start": start, "end": end},
        headers=owner_headers,
    )
    assert report.status_code == 400


def test_report_requires_authentication(client):
    http, _ = client
    response = http.get("/v1/reports/summary")
    assert response.status_code in (401, 403)
