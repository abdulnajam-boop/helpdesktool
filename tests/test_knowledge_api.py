"""API-level tests for GET/POST /v1/knowledge/* against the real HTTP API
(SQLite tier). Proves the knowledge registry's integrity check and its
skill-reference validation both actually run at the API boundary, not
just in the pure-function unit tests in tests/test_knowledge.py.
"""

from __future__ import annotations


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_and_list_issue_definition(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    created = http.post(
        "/v1/knowledge/issues",
        headers=owner_headers,
        json={
            "issue_key": "windows_disk_space_low",
            "title": "Windows disk space low",
            "category": "disk",
            "applicable_os": ["windows"],
            "evidence_requirements": [{"name": "free_disk_percent", "required": True}],
            "mitre_mappings": [],
            "cve_references": [],
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["validated"] is True
    assert body["content_hash"]

    listed = http.get("/v1/knowledge/issues", headers=owner_headers).json()
    assert any(item["issue_key"] == "windows_disk_space_low" for item in listed)


def test_registering_a_new_version_deactivates_the_previous_one(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    body = {
        "issue_key": "linux_disk_space_low",
        "title": "Linux disk space low",
        "category": "disk",
        "applicable_os": ["linux"],
    }
    first = http.post("/v1/knowledge/issues", headers=owner_headers, json=body).json()
    second = http.post("/v1/knowledge/issues", headers=owner_headers, json=body).json()
    assert first["version"] == 1
    assert second["version"] == 2
    active = [
        item
        for item in http.get("/v1/knowledge/issues", headers=owner_headers).json()
        if item["issue_key"] == "linux_disk_space_low"
    ]
    assert len(active) == 1
    assert active[0]["version"] == 2


def test_malformed_mitre_id_is_rejected_with_422(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    response = http.post(
        "/v1/knowledge/issues",
        headers=owner_headers,
        json={
            "issue_key": "bad_mitre",
            "title": "x",
            "category": "security",
            "applicable_os": ["linux"],
            "mitre_mappings": [{"technique_id": "not-a-real-id"}],
        },
    )
    assert response.status_code == 422


def test_viewer_cannot_register_an_issue_definition(client):
    from helpdesktool.db_models import User

    http, factory = client
    identity = _bootstrap_owner(http)
    with factory() as session:
        viewer = User(
            tenant_id=identity["tenant_id"], email="viewer@example.com", role="viewer"
        )
        session.add(viewer)
        session.commit()
        viewer_id = viewer.id
    viewer_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": viewer_id}
    response = http.post(
        "/v1/knowledge/issues",
        headers=viewer_headers,
        json={
            "issue_key": "x",
            "title": "x",
            "category": "disk",
            "applicable_os": ["linux"],
        },
    )
    assert response.status_code == 403


def test_diagnostic_workflow_step_referencing_a_registered_skill_succeeds(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    issue = http.post(
        "/v1/knowledge/issues",
        headers=owner_headers,
        json={
            "issue_key": "service_down",
            "title": "Service is down",
            "category": "service",
            "applicable_os": ["linux"],
        },
    ).json()
    workflow = http.post(
        f"/v1/knowledge/issues/{issue['id']}/workflows",
        headers=owner_headers,
        json={
            "steps": [
                {
                    "step_order": 0,
                    "step_type": "collect_evidence",
                    "description": "check service status",
                },
                {
                    "step_order": 1,
                    "step_type": "remediate",
                    "description": "restart it",
                    "remediation_skill_id": "service.restart",
                    "rollback_skill_id": "service.restore",
                },
                {
                    "step_order": 2,
                    "step_type": "verify",
                    "description": "confirm it's running",
                },
            ]
        },
    )
    assert workflow.status_code == 201, workflow.text

    detail = http.get(f"/v1/knowledge/issues/{issue['id']}", headers=owner_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert len(body["workflows"]) == 1
    assert len(body["workflows"][0]["steps"]) == 3


def test_diagnostic_workflow_step_referencing_an_unregistered_skill_fails_closed(
    client,
):
    """The API-layer proof of the core safety invariant: a workflow can
    never reference a skill id that isn't genuinely registered, however
    plausible it sounds."""
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    issue = http.post(
        "/v1/knowledge/issues",
        headers=owner_headers,
        json={
            "issue_key": "disk_full",
            "title": "Disk full",
            "category": "disk",
            "applicable_os": ["linux"],
        },
    ).json()
    workflow = http.post(
        f"/v1/knowledge/issues/{issue['id']}/workflows",
        headers=owner_headers,
        json={
            "steps": [
                {
                    "step_order": 0,
                    "step_type": "remediate",
                    "description": "wipe temp files",
                    "remediation_skill_id": "disk.force_wipe_everything",
                }
            ]
        },
    )
    assert workflow.status_code == 422
    assert "unregistered" in workflow.json()["detail"]


def test_get_nonexistent_issue_definition_is_404(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    response = http.get(
        "/v1/knowledge/issues/00000000-0000-0000-0000-000000000000",
        headers=owner_headers,
    )
    assert response.status_code == 404


def test_knowledge_source_lifecycle(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    created = http.post(
        "/v1/knowledge/sources",
        headers=owner_headers,
        json={
            "source_organization": "NIST",
            "source_url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
            "retrieval_date": "2026-08-20T00:00:00Z",
            "source_reliability": 0.95,
        },
    )
    assert created.status_code == 201, created.text
    listed = http.get("/v1/knowledge/sources", headers=owner_headers).json()
    assert any(item["source_organization"] == "NIST" for item in listed)
