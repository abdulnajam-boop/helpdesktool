# Production architecture

## Recommended shape: modular monolith plus endpoint agent

Start with one control-plane deployment and one durable relational database, not
microservices. Keep module boundaries explicit so ingestion or execution dispatch can
be extracted only when measured load or isolation requirements justify it.

```text
Windows/Linux Agent -- mTLS --> Control Plane API --> PostgreSQL
       |                              |   |          (RLS + outbox)
 collectors + sandboxed executor     |   +--> Object storage (large artifacts)
 signed skill catalog                +------> Queue/worker (diagnosis + workflows)
                                      +------> LLM provider adapter
 Browser -- OIDC/HTTPS --> Admin UI/API
```

## Trust boundaries and core flow

1. A per-device identity is issued through a single-use enrollment token. Agents use
   short-lived, rotated mTLS certificates and signed requests with monotonic sequence
   numbers to resist replay.
2. Collectors send versioned, bounded telemetry envelopes. The server validates tenant
   ownership; payloads never choose their own tenant authorization context.
3. Rules first correlate observations. An LLM may propose diagnoses and registered
   skill invocations through structured output, but cannot emit executable shell text.
4. The policy engine resolves skill version, device facts, actor permissions, risk,
   maintenance window, and approval requirements. Default is deny.
5. The agent accepts only signed, unexpired jobs addressed to its identity. A
   least-privilege OS-specific executor runs allowlisted operations with resource and
   output limits, verifies postconditions, and invokes declared rollback where needed.
6. Every decision and transition is appended transactionally to audit storage. Ticket
   state follows verified outcomes; unsafe or inconclusive work escalates to a human.

## Logical modules

- **identity:** tenant, user, service principal, device enrollment, OIDC, RBAC.
- **inventory:** devices, hardware/software facts, heartbeats, collector configuration.
- **telemetry:** normalized events, retention tiers, redaction, alert correlation.
- **skills:** immutable versioned manifests, signatures, parameter schemas, executors.
- **automation:** policy, workflow state machine, approvals, dispatch, verify/rollback.
- **diagnosis:** rules, evidence bundles, provider-neutral LLM client, evaluations.
- **tickets:** lifecycle, SLA, comments, evidence, action linkage, escalation.
- **audit:** append-only event ledger, export, retention/legal hold, integrity checks.
- **web:** tenant administration, fleet health, tickets, approvals, audit exploration.

## LLM boundary

Define a provider adapter around structured chat/completion capabilities, timeouts,
retry classification, token/cost accounting, and model metadata. OpenAI-compatible
providers (including configured FreeLLM.net endpoints) are runtime configuration, not
domain dependencies. Credentials remain in a secret manager. Evidence is minimized and
redacted; tenant policy controls whether data may leave the deployment. All proposals
are untrusted inputs revalidated by policy, and deterministic fallback rules continue
to function when providers fail.

## Target repository structure

```text
agent/                 # Go Windows/Linux service, collectors, signed job executor
control-plane/         # API and workers, later migrated from the Python foundation
helpdesktool/           # current Python safety-domain foundation
web/                   # admin dashboard
contracts/             # versioned API/telemetry/skill schemas
deploy/                 # containers, Helm, Terraform examples
docs/                   # ADRs, threat model, operations and architecture
tests/                  # domain, contract, integration and security tests
```

## Production invariants

- Tenant ID comes from authenticated identity and every tenant table uses database RLS.
- Authorization occurs again at the domain boundary, not only in HTTP middleware.
- Jobs are idempotent, signed, expiring, cancellable, and bound to device plus skill hash.
- High-risk changes require independent approval; prohibited actions cannot be approved.
- Secrets and raw sensitive logs are redacted before persistence or model submission.
- Audit writes share a transaction/outbox with state changes and are externally archived.
- Deployments support zero-downtime migrations, backups with restore drills, metrics,
  traces, structured logs, SLOs, health checks, and gradual agent rollout/rollback.

## Implemented control-plane boundary

FastAPI owns synchronous API validation and calls the existing policy/orchestration
domain. SQLAlchemy adapters persist action state and append hash-chained events within
the request transaction. Alembic owns the PostgreSQL schema. The API queues allowlisted
actions but uses a deliberately nonfunctional local executor, preventing the server
from becoming a remote shell. Compose runs migrations before starting the unprivileged,
read-only API container.

Current user authentication uses tenant/user headers validated against an active user
record. This supports tenant isolation and role tests but is not an identity solution;
OIDC access-token validation must replace it. Agent bearer tokens are random and stored
only as hashes, but need expiry, rotation, rate limiting, and eventual mTLS identities.
