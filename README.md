# Helpdesktool

Autonomous, safety-first AI IT help desk platform.

Canonical repository: [abdulnajam-boop/helpdesktool](https://github.com/abdulnajam-boop/helpdesktool)

## Mission

Helpdesktool is designed to monitor endpoints, diagnose common IT problems, select controlled remediation skills, verify outcomes, roll back failed changes, and maintain a complete audit trail with minimal human intervention.

## Core execution model

`Observe -> Diagnose -> Plan -> Risk Check -> Approve (when required) -> Execute -> Verify -> Rollback (if needed) -> Document -> Learn`

The LLM is a planner and skill selector. Privileged actions are performed only by deterministic, policy-controlled executors. Arbitrary unrestricted shell execution is not part of the architecture.

## Initial architecture

- `skills/` — versioned machine-readable skill contracts
- `policies/` — risk, approval, and execution rules
- `orchestrator/` — AI orchestration contract and prompts
- `agent/` — endpoint agent design and OS executors
- `tests/` — contract, policy, and executor tests
- `docs/` — architecture and threat-model documentation

## v1 goals

1. Establish a safe skill contract.
2. Implement read-only diagnostic skills first.
3. Add low-risk remediations with verification and rollback.
4. Introduce approval gates for medium/high-risk operations.
5. Build immutable-style audit events for every decision and action.
6. Support Windows first, followed by Linux and macOS parity.

## Security principles

- Least privilege
- Default deny
- Explicit skill allowlists
- No arbitrary LLM-generated privileged commands
- Input validation
- Command timeouts and output limits
- Approval gates based on risk
- Verification after every mutation
- Rollback where technically possible
- Complete audit trail
- Secrets never written to prompts or logs

## Status

The safety orchestration foundation now includes typed skill/action contracts, a
default-deny policy engine, independent approvals, verification/rollback transitions,
tenant-scoped action access, and a hash-chained audit reference adapter.

See the [repository audit](docs/REPOSITORY_AUDIT.md), [production architecture](docs/ARCHITECTURE.md),
and [prioritized implementation plan](docs/IMPLEMENTATION_PLAN.md). Current persistence
and executors are intentionally interfaces/reference adapters; they are not yet a
deployable endpoint management product.

## Development

Requires Python 3.11 or newer. The foundation has no runtime third-party dependencies.

```bash
python -m pytest
```
