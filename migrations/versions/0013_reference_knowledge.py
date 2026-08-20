"""Phase 13 reference knowledge: seeds a small, deliberately curated set of
issue definitions + diagnostic workflows (not hundreds -- see the 23-phase
roadmap's Phase 13: "build ~5-10 excellent ones, not hundreds").

Ten reference issues, matching Phase 13's own candidate list exactly:
windows/linux disk space, windows/linux service failure, Windows Update
failure, DNS resolution, SSH auth failure, high CPU, unauthorized software,
and security-agent health. Each workflow is grounded in fields the real
collectors (linux_agent/collectors.py, windows_agent/collectors.py) actually
produce -- where no collector exists yet for a signal (Windows Update
history, SSH auth-log correlation), the collect_evidence step says so
honestly rather than inventing a field, per docs/KNOWLEDGE_BASE_AUDIT.md's
"do not overclaim capability" spirit.

Only two remediation skills are registered in this codebase
(diagnostics.collect, service.restart -- see migration 0008), so only the
two service-failure issues and the security-agent-health issue (which may
be running as a monitored service) get a real ``remediate`` step; every
other issue's workflow ends in ``escalate`` -- this is intentionally
honest, not a placeholder: "No generic disk-cleanup skill exists by
design" is already documented in CLAUDE.md, and knowledge must never
describe a remediation capability that doesn't actually exist.

Three of the ten issues (SSH auth failure, unauthorized software,
security-agent health) carry a MITRE mapping with a deliberately moderate
``mapping_confidence`` and explicit ``mapping_evidence`` text stating the
mapping is contextual metadata, not proof -- the concrete embodiment of
Phase 11 ("MITRE ATT&CK as metadata not proof") and Phase 15's correction
that e.g. PowerShell/high-CPU/one signal alone must never become an
automatic technique/compromise claim. The DNS and high-CPU issues each
explicitly restate, in their own step descriptions, the two corrections
docs/KNOWLEDGE_BASE_AUDIT.md calls out by name (never auto-configure
public DNS on enterprise endpoints; high CPU alone is insufficient
evidence) -- so the correction lives in machine-readable knowledge, not
only in a markdown audit doc.

All ten are attributed to a single internally-authored ``KnowledgeSource``
row (source_organization="Helpdesktool Engineering (internal reference
knowledge)") -- deliberately NOT attributed to any external standards
body, since this migration does not itself perform or verify any real
external citation; fabricating that provenance would violate Phase 12's
own principle.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op

from helpdesktool.knowledge import compute_issue_definition_hash

revision = "0013_reference_knowledge"
down_revision = "0012_knowledge_schema"
branch_labels = None
depends_on = None

_SYSTEM_ACTOR = "00000000-0000-0000-0000-000000000000"
_SOURCE_ORG = "Helpdesktool Engineering (internal reference knowledge)"

_KNOWLEDGE_SOURCES = sa.table(
    "knowledge_sources",
    sa.column("id", sa.String),
    sa.column("source_organization", sa.String),
    sa.column("source_url", sa.String),
    sa.column("retrieval_date", sa.DateTime),
    sa.column("source_reliability", sa.Float),
    sa.column("deprecated", sa.Boolean),
    sa.column("created_by", sa.String),
)

_ISSUE_DEFINITIONS = sa.table(
    "issue_definitions",
    sa.column("id", sa.String),
    sa.column("issue_key", sa.String),
    sa.column("version", sa.Integer),
    sa.column("title", sa.String),
    sa.column("description", sa.Text),
    sa.column("category", sa.String),
    sa.column("applicable_os", sa.JSON),
    sa.column("applicable_software_versions", sa.JSON),
    sa.column("evidence_requirements", sa.JSON),
    sa.column("mitre_mappings", sa.JSON),
    sa.column("cve_references", sa.JSON),
    sa.column("escalation_policy", sa.JSON),
    sa.column("source_id", sa.String),
    sa.column("validated", sa.Boolean),
    sa.column("content_hash", sa.String),
    sa.column("active", sa.Boolean),
    sa.column("created_by", sa.String),
)

_DIAGNOSTIC_WORKFLOWS = sa.table(
    "diagnostic_workflows",
    sa.column("id", sa.String),
    sa.column("issue_definition_id", sa.String),
    sa.column("version", sa.Integer),
    sa.column("active", sa.Boolean),
    sa.column("created_by", sa.String),
)

_DIAGNOSTIC_STEPS = sa.table(
    "diagnostic_steps",
    sa.column("id", sa.String),
    sa.column("workflow_id", sa.String),
    sa.column("step_order", sa.Integer),
    sa.column("step_type", sa.String),
    sa.column("description", sa.Text),
    sa.column("remediation_skill_id", sa.String),
    sa.column("verification_description", sa.Text),
    sa.column("rollback_skill_id", sa.String),
    sa.column("reference_description", sa.Text),
)


def _step(
    order: int,
    step_type: str,
    description: str,
    *,
    remediation_skill_id: str | None = None,
    verification_description: str = "",
    rollback_skill_id: str | None = None,
    reference_description: str = "",
) -> dict[str, Any]:
    return {
        "step_order": order,
        "step_type": step_type,
        "description": description,
        "remediation_skill_id": remediation_skill_id,
        "verification_description": verification_description,
        "rollback_skill_id": rollback_skill_id,
        "reference_description": reference_description,
    }


_DISK_EVIDENCE = [
    {"name": "filesystems.free_bytes", "description": "", "required": True},
    {"name": "filesystems.total_bytes", "description": "", "required": True},
]


def _disk_space_issue(issue_key: str, os_name: str, title: str) -> dict[str, Any]:
    return {
        "issue_key": issue_key,
        "title": title,
        "description": (
            "Free disk space on a monitored filesystem has dropped below "
            "the tenant-configured low-disk threshold."
        ),
        "category": "disk",
        "applicable_os": [os_name],
        "evidence_requirements": _DISK_EVIDENCE,
        "mitre_mappings": [],
        "cve_references": [],
        "escalation_policy": {
            "condition": "no automated remediation is available for this issue",
            "escalate_to_role": "operator",
            "priority": "normal",
        },
        "steps": [
            _step(
                0,
                "collect_evidence",
                "Collect filesystems[].free_bytes and filesystems[].total_bytes "
                "for the affected volume from device inventory.",
            ),
            _step(
                1,
                "check_precondition",
                "Confirm the low-space reading is sustained across the "
                "correlation window, not a single transient sample.",
            ),
            _step(
                2,
                "verify",
                "Re-check filesystems[].free_bytes to confirm space has not "
                "already recovered since detection.",
                verification_description=(
                    "filesystems[].free_bytes / filesystems[].total_bytes "
                    "still below threshold"
                ),
            ),
            _step(
                3,
                "escalate",
                "No generic disk-cleanup remediation skill is registered "
                "(deliberate -- see CLAUDE.md); escalate to an operator to "
                "investigate and free space manually.",
            ),
        ],
    }


def _service_failure_issue(
    issue_key: str, os_name: str, title: str, evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "issue_key": issue_key,
        "title": title,
        "description": "A monitored service is not in its expected running state.",
        "category": "service",
        "applicable_os": [os_name],
        "evidence_requirements": evidence,
        "mitre_mappings": [],
        "cve_references": [],
        "escalation_policy": {
            "condition": (
                "restart fails, or the service fails again within a short "
                "window after a successful restart"
            ),
            "escalate_to_role": "operator",
            "priority": "high",
        },
        "steps": [
            _step(
                0,
                "collect_evidence",
                "Collect the monitored service's current state from device inventory.",
            ),
            _step(
                1,
                "check_precondition",
                "Confirm the service is genuinely stopped/failed and not "
                "intentionally disabled by policy or scheduled maintenance.",
            ),
            _step(
                2,
                "remediate",
                "Restart the failed service via the registered service.restart skill.",
                remediation_skill_id="service.restart",
                rollback_skill_id="service.restore",
            ),
            _step(
                3,
                "verify",
                "Confirm the service is running after restart.",
                verification_description="service state is active/running post-restart",
            ),
            _step(
                4,
                "escalate",
                "If the restart fails, or the service fails again shortly "
                "after, escalate for manual investigation rather than "
                "retrying indefinitely.",
            ),
        ],
    }


_WINDOWS_UPDATE_ISSUE: dict[str, Any] = {
    "issue_key": "windows_update_failure",
    "title": "Windows Update failure",
    "description": (
        "Windows Update is failing to install or has left the device in a "
        "prolonged pending-reboot/pending-update state."
    ),
    "category": "updates",
    "applicable_os": ["windows"],
    "evidence_requirements": [
        {"name": "pending_reboot", "description": "", "required": False},
        {"name": "installed_applications", "description": "", "required": False},
    ],
    "mitre_mappings": [],
    "cve_references": [],
    "escalation_policy": {
        "condition": "always -- no remediation skill exists yet for this issue",
        "escalate_to_role": "operator",
        "priority": "normal",
    },
    "steps": [
        _step(
            0,
            "collect_evidence",
            "Collect the update-adjacent telemetry that is actually "
            "available (pending_reboot, installed_applications). No "
            "dedicated Windows Update history/error-code collector exists "
            "yet in windows_agent/collectors.py -- this workflow does not "
            "claim otherwise.",
        ),
        _step(
            1,
            "check_precondition",
            "Confirm this reflects a genuine, sustained failure pattern "
            "(e.g. pending_reboot persisting across multiple heartbeats) "
            "rather than a single in-progress update cycle.",
        ),
        _step(
            2,
            "verify",
            "No automated verification is possible without update-history "
            "telemetry; this step documents what a human should check.",
            verification_description=(
                "Manually review Windows Update history and error codes on the device."
            ),
        ),
        _step(
            3,
            "escalate",
            "No registered remediation skill exists for Windows Update; "
            "escalate to an operator.",
        ),
    ],
}

_DNS_ISSUE: dict[str, Any] = {
    "issue_key": "dns_resolution_failure",
    "title": "DNS resolution failure",
    "description": "A device is failing to resolve DNS queries.",
    "category": "network",
    "applicable_os": ["linux", "windows"],
    "evidence_requirements": [
        {"name": "network.dns_servers", "description": "", "required": True},
    ],
    "mitre_mappings": [],
    "cve_references": [],
    "escalation_policy": {
        "condition": (
            "configured DNS servers deviate from the organization's own "
            "baseline, or resolution fails against the organization's "
            "actual resolvers"
        ),
        "escalate_to_role": "operator",
        "priority": "high",
    },
    "steps": [
        _step(
            0,
            "collect_evidence",
            "Collect network.dns_servers from device inventory.",
        ),
        _step(
            1,
            "check_precondition",
            "Compare configured DNS servers against the organization's "
            "known-good DEVICE_BASELINE/ORGANIZATIONAL_POLICY DNS "
            "configuration. Do NOT assume the correct fix is a public "
            "resolver such as 8.8.8.8/1.1.1.1 just because resolution is "
            "failing -- see docs/KNOWLEDGE_BASE_AUDIT.md's explicit "
            "correction on this exact anti-pattern.",
        ),
        _step(
            2,
            "verify",
            "Confirm resolution succeeds against the organization's actual "
            "configured resolvers, never a substituted public resolver.",
        ),
        _step(
            3,
            "escalate",
            "No registered remediation skill exists for DNS "
            "reconfiguration; escalate to an operator/network team.",
        ),
    ],
}

_SSH_AUTH_ISSUE: dict[str, Any] = {
    "issue_key": "ssh_auth_failure",
    "title": "SSH authentication failure pattern",
    "description": (
        "Repeated SSH authentication failures observed against a Linux endpoint."
    ),
    "category": "auth",
    "applicable_os": ["linux"],
    "evidence_requirements": [],
    "mitre_mappings": [
        {
            "technique_id": "T1110",
            "tactic": "Credential Access",
            "mapping_confidence": 0.3,
            "mapping_evidence": (
                "A repeated-authentication-failure pattern is CONTEXTUAL "
                "metadata consistent with Brute Force, never proof on its "
                "own -- correlate with other signals via "
                "security_classification.classify_security_state before "
                "treating this as suspicious."
            ),
        }
    ],
    "cve_references": [],
    "escalation_policy": {
        "condition": (
            "the failure pattern correlates with other suspicious signals "
            "(multiple source IPs, off-hours timing, targeted privileged "
            "accounts)"
        ),
        "escalate_to_role": "security_team",
        "priority": "high",
    },
    "steps": [
        _step(
            0,
            "collect_evidence",
            "Collect authentication-failure evidence from whatever sources "
            "are available. No dedicated SSH auth-failure collector exists "
            "yet in linux_agent/collectors.py -- this workflow is "
            "diagnosis/escalation-only until such telemetry exists.",
        ),
        _step(
            1,
            "check_precondition",
            "Distinguish a single failed login from a genuinely correlated "
            "pattern (repeated failures, multiple source IPs, off-hours "
            "timing) before treating this as security-relevant -- a single "
            "signal must never alone justify a SUSPICIOUS classification.",
        ),
        _step(
            2,
            "verify",
            "No automated verification applies; this workflow is "
            "diagnosis/escalation only.",
        ),
        _step(
            3,
            "escalate",
            "Escalate to security_team if the pattern correlates with other "
            "suspicious signals; otherwise escalate to an operator as a "
            "routine account-lockout issue.",
        ),
    ],
}

_HIGH_CPU_ISSUE: dict[str, Any] = {
    "issue_key": "high_cpu_usage",
    "title": "Sustained high CPU usage",
    "description": "A device is showing sustained high CPU utilization.",
    "category": "performance",
    "applicable_os": ["linux", "windows"],
    "evidence_requirements": [
        {"name": "cpu.utilization_percent", "description": "", "required": True},
    ],
    "mitre_mappings": [],
    "cve_references": [],
    "escalation_policy": {
        "condition": "sustained high CPU with no operator-approved remediation available",
        "escalate_to_role": "operator",
        "priority": "normal",
    },
    "steps": [
        _step(
            0,
            "collect_evidence",
            "Collect cpu.utilization_percent and, where available, "
            "top_processes_by_memory/process inventory.",
        ),
        _step(
            1,
            "check_precondition",
            "Confirm sustained high utilization across multiple samples, "
            "not a single transient spike. High CPU ALONE -- even alongside "
            "a single other signal such as an open mining port -- is "
            "insufficient evidence of compromise; see "
            "docs/KNOWLEDGE_BASE_AUDIT.md's explicit correction.",
        ),
        _step(
            2,
            "verify",
            "Re-check cpu.utilization_percent after the observation window "
            "to confirm the condition persists.",
        ),
        _step(
            3,
            "escalate",
            "No generic process-management remediation skill is registered; "
            "escalate to an operator. If correlated with other genuinely "
            "suspicious signals, route through "
            "security_classification.classify_security_state rather than "
            "an automatic security escalation based on CPU alone.",
        ),
    ],
}

_UNAUTHORIZED_SOFTWARE_ISSUE: dict[str, Any] = {
    "issue_key": "unauthorized_software_detected",
    "title": "Unauthorized software detected",
    "description": (
        "Installed software was found that is not present in the "
        "organization's approved baseline."
    ),
    "category": "security",
    "applicable_os": ["linux", "windows"],
    "evidence_requirements": [
        {"name": "installed_applications", "description": "", "required": True},
    ],
    "mitre_mappings": [
        {
            "technique_id": "T1204",
            "tactic": "Execution",
            "mapping_confidence": 0.3,
            "mapping_evidence": (
                "Unauthorized software presence is contextual metadata, not "
                "proof of technique execution -- correlate with other "
                "signals before elevating security classification."
            ),
        }
    ],
    "cve_references": [],
    "escalation_policy": {
        "condition": "installed application is not present in the organizational baseline",
        "escalate_to_role": "security_team",
        "priority": "high",
    },
    "steps": [
        _step(
            0,
            "collect_evidence",
            "Collect installed_applications inventory from device telemetry.",
        ),
        _step(
            1,
            "check_precondition",
            "Compare against the organization's own approved-software "
            "baseline/allowlist (DEVICE_BASELINE/ORGANIZATIONAL_POLICY), "
            "not a generic public 'known good' list -- an application "
            "unfamiliar in general is not automatically unauthorized for "
            "this specific organization.",
        ),
        _step(
            2,
            "verify",
            "No automated verification applies; this workflow is "
            "diagnosis/escalation only.",
        ),
        _step(
            3,
            "escalate",
            "Escalate to security_team for review. Never autonomously "
            "uninstall software -- no such remediation skill is registered, "
            "and removing unknown software without review is exactly the "
            "kind of irreversible action this system never performs "
            "autonomously.",
        ),
    ],
}

_SECURITY_AGENT_HEALTH_ISSUE: dict[str, Any] = {
    "issue_key": "security_agent_health_degraded",
    "title": "Security agent health degraded",
    "description": (
        "A monitored security agent (EDR/AV) service is not in its "
        "expected running state."
    ),
    "category": "security",
    "applicable_os": ["linux", "windows"],
    "evidence_requirements": [
        {"name": "services[].active", "description": "", "required": False},
    ],
    "mitre_mappings": [
        {
            "technique_id": "T1562.001",
            "tactic": "Defense Evasion",
            "mapping_confidence": 0.4,
            "mapping_evidence": (
                "A disabled/degraded security agent is consistent with "
                "Impair Defenses: Disable or Modify Tools, but this alone "
                "does not confirm malicious tampering versus e.g. a "
                "legitimate update or crash -- correlate with other "
                "signals before treating as compromise."
            ),
        }
    ],
    "cve_references": [],
    "escalation_policy": {
        "condition": (
            "the agent remains degraded after restart, or restart is not applicable"
        ),
        "escalate_to_role": "security_team",
        "priority": "critical",
    },
    "steps": [
        _step(
            0,
            "collect_evidence",
            "Collect the security agent's service health status, if it is "
            "registered as a monitored service.",
        ),
        _step(
            1,
            "check_precondition",
            "Distinguish an intentional/approved maintenance state (e.g. a "
            "scheduled agent update) from an unexpected disablement before "
            "treating this as security-relevant.",
        ),
        _step(
            2,
            "remediate",
            "Restart the security agent service, if it is registered as a "
            "monitored systemd/Windows service.",
            remediation_skill_id="service.restart",
            rollback_skill_id="service.restore",
        ),
        _step(
            3,
            "verify",
            "Confirm the security agent service is active/running after restart.",
        ),
        _step(
            4,
            "escalate",
            "If the agent remains down after restart, or the degradation "
            "is a process crash rather than a stopped service, escalate to "
            "security_team immediately. A single degraded-health signal "
            "alone must never be treated as CONFIRMED_COMPROMISE -- that "
            "classification is reachable only via an explicit, "
            "independently-set authoritative confirmation (see "
            "security_classification.py).",
        ),
    ],
}

_ISSUES: list[dict[str, Any]] = [
    _disk_space_issue("windows_disk_space_low", "windows", "Windows disk space low"),
    _disk_space_issue("linux_disk_space_low", "linux", "Linux disk space low"),
    _service_failure_issue(
        "windows_service_failure",
        "windows",
        "Windows service failure",
        [
            {"name": "services[].state", "description": "", "required": True},
            {"name": "services[].exists", "description": "", "required": True},
        ],
    ),
    _service_failure_issue(
        "linux_systemd_service_failure",
        "linux",
        "Linux systemd service failure",
        [
            {"name": "services[].active", "description": "", "required": True},
            {"name": "services[].sub", "description": "", "required": True},
        ],
    ),
    _WINDOWS_UPDATE_ISSUE,
    _DNS_ISSUE,
    _SSH_AUTH_ISSUE,
    _HIGH_CPU_ISSUE,
    _UNAUTHORIZED_SOFTWARE_ISSUE,
    _SECURITY_AGENT_HEALTH_ISSUE,
]

_ISSUE_KEYS = [issue["issue_key"] for issue in _ISSUES]


def upgrade() -> None:
    now = datetime.now(UTC)
    source_id = str(uuid.uuid4())
    op.bulk_insert(
        _KNOWLEDGE_SOURCES,
        [
            {
                "id": source_id,
                "source_organization": _SOURCE_ORG,
                "source_url": "",
                "retrieval_date": now,
                "source_reliability": 0.75,
                "deprecated": False,
                "created_by": _SYSTEM_ACTOR,
            }
        ],
    )

    issue_rows: list[dict[str, Any]] = []
    workflow_rows: list[dict[str, Any]] = []
    step_rows: list[dict[str, Any]] = []

    for issue in _ISSUES:
        issue_id = str(uuid.uuid4())
        content_hash = compute_issue_definition_hash(
            issue_key=issue["issue_key"],
            version=1,
            category=issue["category"],
            applicable_os=frozenset(issue["applicable_os"]),
            evidence_requirements=issue["evidence_requirements"],
            mitre_mappings=issue["mitre_mappings"],
            cve_references=issue["cve_references"],
        )
        issue_rows.append(
            {
                "id": issue_id,
                "issue_key": issue["issue_key"],
                "version": 1,
                "title": issue["title"],
                "description": issue["description"],
                "category": issue["category"],
                "applicable_os": issue["applicable_os"],
                "applicable_software_versions": {},
                "evidence_requirements": issue["evidence_requirements"],
                "mitre_mappings": issue["mitre_mappings"],
                "cve_references": issue["cve_references"],
                "escalation_policy": issue["escalation_policy"],
                "source_id": source_id,
                "validated": True,
                "content_hash": content_hash,
                "active": True,
                "created_by": _SYSTEM_ACTOR,
            }
        )

        workflow_id = str(uuid.uuid4())
        workflow_rows.append(
            {
                "id": workflow_id,
                "issue_definition_id": issue_id,
                "version": 1,
                "active": True,
                "created_by": _SYSTEM_ACTOR,
            }
        )
        for step in issue["steps"]:
            step_rows.append(
                {
                    "id": str(uuid.uuid4()),
                    "workflow_id": workflow_id,
                    **step,
                }
            )

    op.bulk_insert(_ISSUE_DEFINITIONS, issue_rows)
    op.bulk_insert(_DIAGNOSTIC_WORKFLOWS, workflow_rows)
    op.bulk_insert(_DIAGNOSTIC_STEPS, step_rows)


def downgrade() -> None:
    keys = ", ".join(f"'{key}'" for key in _ISSUE_KEYS)
    op.execute(
        f"""
        DELETE FROM diagnostic_steps WHERE workflow_id IN (
            SELECT dw.id FROM diagnostic_workflows dw
            JOIN issue_definitions idf ON idf.id = dw.issue_definition_id
            WHERE idf.issue_key IN ({keys})
        )
        """
    )
    op.execute(
        f"""
        DELETE FROM diagnostic_workflows WHERE issue_definition_id IN (
            SELECT id FROM issue_definitions WHERE issue_key IN ({keys})
        )
        """
    )
    op.execute(f"DELETE FROM issue_definitions WHERE issue_key IN ({keys})")
    op.execute(
        f"DELETE FROM knowledge_sources WHERE source_organization = '{_SOURCE_ORG}'"
    )
