# Repository audit (2026-08-15)

## Method and baseline

The repository was inspected from the current `work` branch, including tracked files,
history, configuration, and working tree. The baseline commit (`88287d0`) contained
only `README.md`; there was no application code, dependency manifest, test suite,
deployment configuration, endpoint agent, API, UI, database schema, or CI pipeline.

## Capability assessment before this change

| Capability | Status | Evidence / gap |
| --- | --- | --- |
| Product intent and safety principles | Defined | README describes the execution loop, default deny, approvals, rollback, and audit. |
| Endpoint agents | Missing | No Windows/Linux process, enrollment, updater, collectors, or executor. |
| Secure transport | Missing | No identity, mTLS, rotation, protocol, replay defense, or server endpoint. |
| Inventory and telemetry | Missing | No schemas, ingestion, storage, retention, or collectors. |
| Diagnosis / LLM abstraction | Missing | No provider interface, prompt boundary, evaluation, or model configuration. |
| Remediation safety core | Design only | Principles existed, but no executable contracts or policy state machine. |
| Ticketing and dashboard | Missing | No domain model, API, or frontend. |
| Multi-tenancy and RBAC | Missing | No identity or authorization implementation. |
| Approval, audit, rollback | Design only | Requirements existed without implementation or persistence. |
| Operations | Missing | No container, migrations, CI/CD, observability, backup, or runbooks. |

## What this increment establishes

This increment deliberately implements the first trust boundary rather than a broad,
nonfunctional SaaS shell: typed action and skill contracts, a fail-closed allowlist,
OS constraints, risk-based approval, separation of duties, tenant-scoped lookup,
execution verification, rollback transitions, and hash-chained audit events. The
in-memory adapters are testable reference implementations, not production storage.

## Known limitations

- The original reference adapters remain process-local, while the control plane now
  persists state and uses database transactions, idempotency keys, leases, and an outbox.
- The device OS context passed at submission is temporary. The control plane must
  resolve authoritative, signed inventory server-side.
- Authentication, authorization roles, approval expiry/quorum, artifact signing,
  transport security, secret redaction, and durable audit retention remain unbuilt.
- Executors are interfaces only. No command execution is shipped until sandboxing,
  signed skills, bounded output, timeout, and least-privilege service identities exist.

## Control-plane increment

The repository now includes a runnable FastAPI/PostgreSQL control plane, Alembic
migration, Docker Compose deployment, persistent action/audit adapters, tenant-scoped
queries, basic roles, hashed device credentials, request idempotency, telemetry, ticket,
action, approval, and audit APIs. Header-based user identity and the bootstrap token are
development foundations, not production authentication. PostgreSQL RLS, OIDC, token
rotation, audit sequence locking, signed agent jobs, and outbox observability remain required.

## Capability gap analysis (2026-08-16)

| Capability | Classification | Current assessment |
| --- | --- | --- |
| FastAPI control plane and PostgreSQL schema | `PARTIAL` | Runnable prototype; route modularization and production operations remain. |
| Linux endpoint inventory and one remediation | `PARTIAL` | Useful v0.1; identity, upgrades and crash-safe execution journal remain. |
| Windows endpoint agent | `MISSING` | Explicitly deferred until Linux trust hardening. |
| Policy, approval and deterministic execution | `PARTIAL` | Core invariants work; versioned registry and tenant policy administration remain. |
| Tenant isolation | `SECURITY RISK` | Application filters exist; OIDC and PostgreSQL RLS are absent. |
| Audit history | `NEEDS REFACTOR` | Persistent chained events exist; concurrent sequence locking and immutable export are absent. |
| Incident engine | `MISSING` | Tickets do not yet correlate observations into incidents. |
| Event/integration outbox | `DONE` | Canonical events, transactional fan-out, signed webhooks and bounded worker implemented for MVP. |
| n8n integration | `DONE` | Generic webhook compatibility; n8n remains outside the security boundary. |
| AI/RAG/provider abstraction | `MISSING` | No model calls or provider coupling exist. |
| Secrets abstraction | `PARTIAL` | Webhooks use a narrow environment provider; cloud providers remain. |
| Dashboard/frontend | `MISSING` | No frontend exists. |
| CI/CD and production infrastructure | `MISSING` | Compose exists; CI, RLS tests, Helm/Terraform and deployment controls do not. |
