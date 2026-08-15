# Prioritized implementation plan

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
database, many microservices, or a large skill catalog before the first remediation
slice is safely deployed and used. They increase blast radius and delay validation.
