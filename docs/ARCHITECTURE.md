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

## Linux endpoint agent v0.1

The Python agent separates configuration/enrollment, HTTP transport, `/proc`-based
collectors, job validation, deterministic execution, verification/result reporting,
and local logging. Jobs are tenant/device-filtered, atomically claimed with a 60-second
lease and one-time claim secret, and protected by server plus local replay records.

`service.restart` accepts exactly one `service` parameter. The same exact unit must be
allowlisted on the server and endpoint. The executor passes an argument vector directly
to `systemctl`, enforces timeouts, verifies structured unit state, and attempts to
restore the prior active/inactive state after restart or verification failure. The
agent runs unprivileged; narrowly scoped PolicyKit authorization is an operator-owned
deployment prerequisite.

The v0.1 local replay file prevents normally completed actions from being executed
twice, but it is not a durable execution journal. A process or host crash after the
restart and before result acknowledgement can leave a claimed job unresolved. The next
milestone must add resumable local journaling plus server-side lease recovery without
blindly repeating a mutation.

## Domain events and external integration boundary

Audit-producing state transitions map to versioned canonical domain events inside the
same PostgreSQL transaction. Active tenant subscriptions are expanded into durable
delivery rows before commit. A separate worker claims pending rows, resolves a signing
secret through the `SecretsProvider` interface, signs the canonical JSON body, and sends
it through the provider-neutral `IntegrationProvider` contract.

The initial provider is a generic HTTP webhook suitable for n8n. HTTPS is mandatory by
default; credential-bearing URLs and destinations resolving to loopback, private,
link-local, multicast or otherwise non-global addresses fail closed. Resolution is
rechecked at delivery time, retries are bounded with exponential backoff, non-retryable
4xx responses and exhausted deliveries enter `dead_letter`, and response bodies are not
persisted. Production egress should additionally traverse a policy-enforcing proxy to
close DNS rebinding and network-routing gaps that application validation alone cannot.

n8n receives facts and lifecycle notifications only. It cannot modify policy, approve
actions, issue endpoint jobs, perform rollback, or cross tenant boundaries. Future Jira,
ServiceNow, Slack, Teams and email adapters implement the same integration interface;
they do not become dependencies of the core incident/remediation state machine.
