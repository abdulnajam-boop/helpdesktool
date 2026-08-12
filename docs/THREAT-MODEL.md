# Initial Threat Model

## Assets

- endpoint execution authority
- tenant data
- device identities and credentials
- administrator identities
- approval decisions
- remediation/playbook packages
- incident and ticket data
- audit evidence
- secrets and integration credentials

## Primary trust boundaries

1. endpoint device <-> cloud gateway
2. ingestion <-> internal event/data services
3. LLM/orchestrator <-> deterministic policy engine
4. policy engine <-> remediation workflow
5. cloud control plane <-> endpoint executor
6. administrator browser <-> dashboard/API
7. tenant A <-> tenant B
8. build/release system <-> production agent/playbooks

## Major threats and controls

### Arbitrary model execution

Threat: model-generated commands obtain endpoint administrator privileges.

Controls: registered skill IDs only, signed/versioned playbooks, typed parameters, deterministic executor, default-deny policy, no raw privileged shell tool exposed to the model.

### Prompt injection through endpoint evidence

Threat: log lines, process names, files, tickets, or user-controlled strings instruct the model to violate policy.

Controls: endpoint evidence is untrusted data, strict context separation, structured evidence envelopes, policy authorization independent of model output, allow-listed skills only.

### Cross-tenant data exposure

Controls: tenant_id on tenant-owned records, PostgreSQL RLS, authorization tests, tenant-scoped queues/storage keys, no model context spanning tenants unless explicitly aggregated through an authorized reporting path.

### Device impersonation

Controls: enrollment ceremony, short-lived mTLS device credentials, rotation, revocation, device binding, signed/replay-resistant envelopes.

### Command replay

Controls: command IDs, nonce/sequence metadata, issue/expiry times, idempotency keys, endpoint replay cache, server-side command state.

### Malicious or compromised playbook

Controls: code review, CI tests, signing, version pinning, hash verification, canary rollout, policy constraints, rollback, kill switch.

### Unsafe parameters

Controls: JSON Schema/typed validation, allow-lists, canonical path validation, bounds, regex/enum constraints, no string concatenation into shell commands where structured APIs are available.

### Approval forgery or reuse

Controls: authenticated approver identity, role checks, action/target binding, expiration, single-use approval token, immutable audit event.

### Secret leakage

Controls: Vault/KMS-backed secrets, short-lived credentials, redaction, no secrets in LLM prompts, tickets, standard telemetry, or command output archives.

### Agent privilege abuse

Controls: least privilege, split privileged helper where practical, narrow OS permissions, local policy enforcement, signed commands, bounded executors.

### Audit tampering

Controls: append-only event model, immutable object archive, hashes/hash-chain-compatible records, restricted write identities, independent retention.

### Autonomous self-modification

Threat: system learns a successful fix and deploys new executable behavior without review.

Controls: learning produces offline candidates only; test, evaluate, review, sign, version, canary, and explicitly release changes.

## Fail-safe behavior

The system must fail closed when:

- device identity cannot be verified
- tenant scope is ambiguous
- skill is missing or unsigned
- parameters fail validation
- policy cannot produce an authorization decision
- required approval is missing/expired
- command envelope is replayed/expired
- verification cannot establish success

Uncertainty in these controls results in no mutation and an escalation/audit event.
