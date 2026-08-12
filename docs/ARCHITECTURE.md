# Helpdesktool Architecture

## Product target

Helpdesktool is a multi-tenant autonomous IT help desk for organizations, starting with a Windows-first pilot and expanding to macOS and Linux. The endpoint agent should require minimal human involvement after installation.

The system monitors device health, detects incidents, diagnoses likely causes, executes approved deterministic remediations, verifies outcomes, rolls back unsuccessful changes, manages ticket lifecycle, and reports unresolved problems to administrators.

## MVP scope

Initial pilot target: approximately 25 devices, with architecture capable of expanding toward 25-100 devices without changing the trust model.

Windows 10/11 first. Tenant boundaries exist from day one even if the first pilot uses one organization.

### Initial telemetry

- CPU
- memory
- disk capacity and pressure
- services
- bounded Windows Event Log signals
- network and DNS health
- update posture
- installed software inventory where policy permits
- endpoint-agent health

### Initial autonomous capabilities

- up to 10 deterministic issue detectors
- five reversible remediation playbooks
- automatic ticket creation and updates
- risk-based approvals
- post-action verification
- rollback on failed remediation where possible
- complete audit history
- administrator dashboard
- daily management summary

## Trust boundary

The LLM is not the endpoint administrator.

The LLM may:

- interpret bounded evidence
- propose hypotheses
- choose from registered skills
- explain decisions
- summarize incidents and reports

The LLM may not:

- execute arbitrary privileged shell commands
- invent unregistered skills
- bypass policy or approvals
- modify production execution policy
- self-modify production skill implementations
- report success without verification evidence

## Request lifecycle

Observe -> Diagnose -> Plan -> Risk Check -> Approval (when required) -> Execute -> Verify -> Rollback (if failed) -> Ticket/Audit -> Learn offline

## Logical components

### Endpoint agent

A signed Windows service, implemented in Go for the production agent, owns endpoint identity, bounded telemetry collection, local executor invocation, health reporting, command verification, and secure communications.

### Gateway / ingestion

Receives authenticated endpoint envelopes over mTLS, validates device and tenant identity, rejects replayed or malformed messages, and publishes normalized events.

### Detection and incident service

Runs deterministic detectors first. Creates or correlates incidents and provides bounded evidence to the AI diagnosis layer when reasoning adds value.

### Orchestrator

Selects registered skills and produces structured plans. It never receives unrestricted endpoint execution authority.

### Policy / authorization

A deterministic policy engine decides whether a proposed action is allowed, denied, or requires approval based on tenant policy, device state, skill risk, permissions, and requested scope.

OPA is the preferred policy engine for the initial architecture.

### Durable workflow engine

Temporal is the preferred workflow engine for incident workflows, retries, timeouts, approvals, verification, rollback, and escalation.

### Remediation runtime

Executes signed, allow-listed, versioned playbooks with typed inputs, preconditions, idempotency controls, bounded timeouts, verification, and rollback metadata.

### Ticket provider

Ticketing sits behind a provider interface. iTop can be adapted as an initial open-source backend while keeping the platform independent of any single ticket system.

### Data layer

PostgreSQL is the system of record. Row-level security is required for tenant isolation. Immutable or append-only audit material should also be archived to S3-compatible object storage.

### Event backbone

NATS JetStream is the preferred lightweight event backbone for endpoint telemetry and internal events.

### Observability

OpenTelemetry provides traces, metrics, and structured logs for platform services.

### Dashboard

React/Next.js administrator UI for fleet health, incidents, approvals, tickets, audit history, policy state, and daily reports.

## Security model

- short-lived device identity and mTLS credentials
- credential rotation
- signed command/playbook envelopes
- replay resistance
- default-deny policy
- least privilege
- typed inputs and strict validation
- no plaintext secrets in prompts or logs
- single mutating workflow per device by default
- idempotency keys for mutating operations
- timeouts, retry limits, and circuit breakers
- separation of duties for high-impact approvals
- expiring, non-replayable approval decisions
- append-only/hash-chain-friendly audit events
- software signing and SBOM generation
- staged/canary deployment of new skills

## Controlled learning

Production agents do not rewrite their own code, policies, or skills. Successful incidents may produce candidate knowledge/runbook improvements. Those changes are evaluated offline, tested, reviewed, versioned, canaried, and made rollbackable before release.

## Deployment direction

Local development: Docker Compose.

Initial cloud/staging: managed Kubernetes or an equivalent managed container platform. Infrastructure is defined with Terraform.

The first engineering milestone is not a multi-agent swarm. It is a secure one-device vertical slice proving endpoint identity, telemetry, incident creation, policy evaluation, one safe playbook, verification, audit, and dashboard visibility. After that, expand toward a 25-device pilot.
