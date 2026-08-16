# Prioritized implementation plan

Each item identifies its purpose, affected modules, dependencies, security work, tests,
and objective completion gate. Priorities protect the execution trust boundary before
adding AI or more remediation skills.

## P0 — security and blockers

### 1. Transactional events and external webhook outbox — implemented

- **Purpose:** expose stable tenant events to n8n and other consumers without placing
  integrations in the authorization path.
- **Modules:** `events.py`, `integrations.py`, `webhook_worker.py`, persistence, API,
  migration `0003`, Compose.
- **Dependencies:** existing PostgreSQL/SQLAlchemy; Python standard-library HTTP client.
- **Security:** HMAC signatures, secret references, SSRF URL policy, HTTPS default,
  tenant-scoped subscriptions, bounded retries/timeouts, sanitization, no security APIs.
- **Tests:** event schema/redaction, URL denial, secret namespace, signature, transaction
  fan-out, retry/dead-letter, tenant isolation.
- **Done:** business event and delivery rows commit atomically; a signed payload reaches
  a configured consumer; failure cannot roll back or authorize core Helpdesk state.

### 2. Production identity and tenant isolation — next

- **Purpose:** replace forgeable identity headers and make cross-tenant access fail at
  both application and database layers.
- **Modules:** `auth.py`, API dependencies, database session context, migrations, tests.
- **Dependencies:** selected OIDC provider/JWKS library and PostgreSQL RLS.
- **Security:** issuer/audience/algorithm validation, short token lifetime, permission
  claims, tenant context set transaction-locally, deny-by-default RLS policies.
- **Tests:** invalid/expired/wrong-audience JWTs, role matrix, forced cross-tenant SQL,
  connection-pool tenant-context leakage, PostgreSQL integration tests.
- **Done:** no client-provided tenant/user identity is trusted; every tenant table is RLS
  protected and negative tests prove isolation.

### 3. Agent and job trust hardening

- **Purpose:** make endpoint identity, delivery and retry behavior safe under disconnects
  and crashes.
- **Modules:** Linux client/agent, enrollment APIs, action schema, outbox, migrations.
- **Dependencies:** internal CA or managed PKI; OS key storage.
- **Security:** rotated mTLS certificates, signed/versioned/device-bound envelopes,
  monotonic replay counters, durable local execution journal, safe lease recovery.
- **Tests:** certificate rotation/revocation, replay, wrong-device signature, crash at each
  action phase, expired leases, duplicate delivery, 100-device soak.
- **Done:** a crash cannot silently repeat a mutation and revoked devices cannot poll or
  report jobs.

## P1 — MVP core

### 4. Incident engine and ticket automation

- **Purpose:** correlate observations into durable incidents and drive ticket lifecycle,
  escalation, verification-based resolution and reopen behavior.
- **Modules:** new incident domain/service, telemetry ingestion, tickets, events, schema.
- **Dependencies:** tasks 1–3; no AI required.
- **Security:** tenant-scoped evidence, redaction, deterministic rules, bounded retention.
- **Tests:** deduplication, correlation windows, severity transitions, SLA escalation,
  resolve/reopen, cross-tenant evidence denial.
- **Done:** a real health observation produces one correlated incident/ticket and its
  verified remediation result updates the lifecycle deterministically.

### 5. Versioned remediation action registry

- **Purpose:** replace hard-coded API/agent skill lists with signed, immutable contracts
  defining OS, schema, risk, permissions, timeout, verification, rollback and audit.
- **Modules:** skills domain, policy, API, Linux agent, migrations, signing pipeline.
- **Dependencies:** task 3 job signatures.
- **Security:** schema validation at proposal/server/agent boundaries, immutable hashes,
  downgrade resistance, no arbitrary command representation.
- **Tests:** manifest tampering, unsupported OS/version, malformed parameters, risk drift,
  signature failure, rollback contract.
- **Done:** `service.restart` executes from one versioned contract hash validated by all
  boundaries; unknown or altered contracts fail closed.

## P2 — automation and integrations

- Add provider adapters for Jira, ServiceNow, Slack, Teams and email only after generic
  webhook usage identifies a real gap. Add delivery metrics, tenant quotas, endpoint
  allowlists and operator replay/dead-letter controls.
- Integrate cloud `SecretsProvider` adapters (AWS, GCP, Azure, HashiCorp Vault) using
  workload identity. Never distribute unrestricted human vault credentials to agents.

## P3 — advanced AI

- Define a provider-neutral `AIProvider` for OpenAI, Anthropic, Gemini, OpenRouter,
  Ollama and OpenAI-compatible endpoints.
- Add redacted evidence bundles, structured diagnosis/action proposals, model/cost audit,
  deterministic fallback, evaluations and prompt-injection tests.
- AI output remains untrusted and must pass the action registry, policy and approval path.

## P4 — enterprise features

- SSO/SCIM, fine-grained permissions, approval quorum/expiry, policy-as-code, immutable
  audit export/legal hold, HA workers, backup/restore drills, regional data controls,
  signed staged agent upgrades, SBOM/provenance and enterprise integration governance.

## P5 — marketing and developer tooling

- Evaluate `video-shotcraft` as an isolated Codex/Remotion tool after license review.
- Consider Excalidraw only for isolated topology/incident diagram export after the core
  operator workflow is validated. Neither belongs in the production execution runtime.
## P0 — establish the safe vertical slice

1. **Safety-domain contracts (implemented in this increment):** fail-closed policy,
   approval separation, verified execution, rollback states, and chained audit adapter.
2. **Durable control-plane skeleton:** PostgreSQL schema with tenant RLS, migrations,
   transactional audit/outbox, OIDC authentication, RBAC, REST API, idempotency, and
   OpenAPI contracts. Exit: cross-tenant and concurrency integration tests pass.
3. **Linux agent read-only pilot:** enrollment and certificate rotation, heartbeat,
   signed job polling/stream, system inventory and service/disk/memory diagnostics. Run
   unprivileged with explicit capability elevation. Exit: 100-device soak and upgrade test.
4. **One end-to-end remediation:** restart an allowlisted service with precheck,
   approval policy, timeout, postcheck, rollback/escalation, ticket linkage, and complete
   audit. This is the smallest useful product slice to validate with design partners.

## P1 — make the pilot operable

5. Ticket lifecycle/SLA and a minimal admin UI for fleet health, evidence, approvals,
   action progress, audit history, and human escalation.
6. Windows service agent with equivalent signed transport and initial collectors using
   documented Windows APIs rather than arbitrary PowerShell.
7. Provider-neutral diagnosis interface, rule-based baseline, redaction, structured LLM
   proposals, budgets, circuit breakers, evaluation fixtures, and OpenAI-compatible
   endpoint configuration.
8. Production delivery: containers, SBOM/signing, dependency scans, CI quality gates,
   Helm deployment, secrets integration, backup/restore, dashboards, alerts, and runbooks.

## P2 — expand only after pilot evidence

9. Additional signed skills driven by real ticket frequency and measured resolution ROI.
10. Telemetry retention tiers, artifact storage, integrations, SSO/SCIM, advanced RBAC,
    approval quorum/expiry, policy-as-code, HA workers, and staged agent update rings.

## Explicitly deferred

Do not build a general remote shell, autonomous self-authored scripts, a custom metrics
database, many microservices, a Windows agent, dashboard, or large skill catalog before
P0 trust hardening and the deterministic incident vertical slice are validated.
database, many microservices, or a large skill catalog before the first remediation
slice is safely deployed and used. They increase blast radius and delay validation.
