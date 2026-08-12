# Windows-first MVP Roadmap

## Milestone 0 - Threat model and contracts

- define tenant/device/incident/skill/command/audit schemas
- define trust boundaries
- define device enrollment and credential rotation
- define replay-resistant command envelope
- define risk and approval levels
- define audit retention requirements

Exit: security contracts are testable before remote execution exists.

## Milestone 1 - One-device trust and telemetry spine

- signed Go Windows service skeleton
- device enrollment
- short-lived mTLS identity
- heartbeat and agent health
- CPU, memory, disk, service and network telemetry
- bounded Windows Event Log collection
- ingestion API
- PostgreSQL persistence with tenant_id on all tenant-owned records
- append-only audit event creation

Exit: one Windows endpoint can enroll and send authenticated bounded telemetry end-to-end.

## Milestone 2 - Deterministic detection and ticketing

Implement initial detectors for conditions such as:

1. low disk space
2. sustained CPU pressure
3. sustained memory pressure
4. monitored service stopped
5. DNS resolution failure
6. gateway/internet connectivity failure
7. pending reboot
8. update posture problem
9. repeated application/service error signal
10. endpoint agent degraded

Add incident correlation and ticket-provider interface.

Exit: telemetry creates deduplicated incidents and tickets without an LLM being required for basic detection.

## Milestone 3 - Safe remediation runtime

First five playbooks should be reversible or low blast radius. Candidate set:

1. restart an allow-listed service
2. renew/recover bounded network configuration where policy allows
3. clear approved temporary/cache locations with strict path guards
4. restart an allow-listed application/process
5. repair/restart the Helpdesktool agent itself through a watchdog mechanism

Each playbook requires typed inputs, preconditions, idempotency key, timeout, verification, audit output, and rollback or explicit non-rollbackable declaration.

Exit: one incident can progress detection -> policy -> execution -> verification -> ticket closure with no arbitrary shell generation.

## Milestone 4 - Approval and administrator UI

- approval queue
- role-aware authorization
- approval expiry and anti-replay
- fleet health view
- incident detail timeline
- ticket status
- remediation evidence
- audit history
- policy visibility

Initially require approval for service restarts and other disruptive actions until field evidence supports narrower preapproval policies.

Exit: an administrator can understand and control every mutating action.

## Milestone 5 - AI diagnosis/orchestration

- bounded incident context builder
- registered-skill retrieval
- structured hypothesis and confidence output
- skill selection
- policy handoff
- escalation when confidence/evidence is insufficient
- ticket/user-facing summaries

Exit: AI improves diagnosis and orchestration without receiving arbitrary endpoint execution authority.

## Milestone 6 - Adversarial evaluation

Test:

- prompt injection from logs/file names/process names
- malicious skill parameters
- cross-tenant access attempts
- replayed commands
- expired approvals
- agent impersonation
- unsafe path inputs
- command timeout behavior
- duplicate workflow delivery
- failed verification
- rollback failure
- LLM hallucinated skill IDs

Exit: unsafe requests fail closed and produce useful audit evidence.

## Milestone 7 - 25-device pilot

- staged signed agent rollout
- canary skill versions
- SLOs and alerting
- daily management report
- incident/resolution metrics
- false-positive review
- remediation success/rollback metrics
- resource usage and agent footprint measurements

Exit: demonstrate safe autonomous handling of a narrow, measurable class of real help-desk incidents.

## Later

After the Windows pilot is stable:

- macOS endpoint support
- Linux endpoint support
- additional ticket providers
- knowledge/RAG with Qdrant or OpenSearch only when justified by retrieval needs
- broader application remediation
- specialized worker agents and manager/reporting agent
- larger multi-tenant production rollout
