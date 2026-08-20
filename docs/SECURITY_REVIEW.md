# Security review — v0.1.0-rc1

Date: 2026-08-20. Scope: an adversarial review of `main` at commit `9e67d64`,
performed as part of release-candidate hardening. This is a code-and-test-based
review (static reading plus real adversarial tests run against the actual API,
real Postgres, and real Docker images) — not a third-party penetration test.
See `docs/RELEASE_READINESS.md` for what still requires one.

Every finding below was verified by making the attack fail against real
running code, not by inspection alone. Two real, exploitable gaps were found
and fixed during this pass; both are marked **FIXED** with the commit that
closed them. Nothing was weakened to make a test pass — every fix tightens a
check, never loosens one.

## Findings

### FIXED — SSRF via unfollowed-redirect bypass in webhook delivery

**Severity:** High. **Location:** `helpdesktool/integrations.py`,
`SignedWebhookProvider.deliver`.

`validate_webhook_url` resolves the webhook's hostname and rejects any
non-public IP (loopback, RFC1918 private ranges, link-local, including the
`169.254.169.254` cloud metadata endpoint) — but this check only ever ran
against the URL a subscription was registered/re-validated with.
`SignedWebhookProvider.deliver` then called `urllib.request.urlopen` with its
default opener, which transparently follows HTTP 3xx redirects to *any*
destination the remote server names, with zero re-validation. A webhook
target that returned `302 Location: http://169.254.169.254/latest/meta-data/
iam/security-credentials/...` (or `http://localhost:6379/`, or any internal
address) would have been followed and the response returned as if it were
the legitimate delivery target's response.

Reproduced against a real local HTTP server before fixing (confirmed the
redirect was followed); fixed by adding `_NoRedirectHandler`, a custom
`urllib.request.HTTPRedirectHandler` that refuses every redirect — the 3xx
response is now surfaced to the caller as an ordinary non-2xx delivery
outcome instead of being followed. Regression test:
`tests/test_integrations.py::test_webhook_delivery_refuses_to_follow_a_redirect_to_a_private_address`,
which uses a real local `HTTPServer`, not a mock, so it proves actual network
behavior. Also added
`test_webhook_url_rejects_every_non_global_ip_class`, parametrized across
loopback/metadata/link-local/three RFC1918 ranges/unspecified, to pin the
existing (already-correct) `validate_webhook_url` behavior explicitly rather
than leaving it implied by two cases.

Fixed in commit `e9120d7`.

### FIXED — frontend infinite fetch loop on the Reports page

**Severity:** Medium (self-inflicted denial-of-service against the API;
also a broken feature). **Location:** `frontend/src/pages/Reports.tsx`.

Not a traditional security vulnerability, but found during this pass's
browser/UX validation and reported here because of its effect under the
rate limiter added in the same hardening line of work
(`helpdesktool/hardening.py`'s `RateLimitMiddleware`): the Reports page
computed `new Date()` directly in the component render body to build its
`/v1/reports/summary` query string. Because that produces a
millisecond-different timestamp on every render, `useApi`'s effect
(keyed on the request path) re-fired on every render, which triggered a
state update, which triggered another render — an infinite loop that
hammered the API with dozens of requests per second and never let a single
response actually render (the page was stuck on "Loading…" forever).
Reproduced live with a real browser (Playwright, against the real
production Docker images) before fixing — see `tests/e2e/`. In a
production deployment with the rate limiter active, this specific bug
would have caused any operator who opened the Reports page to have their
own IP throttled by their own client. Fixed by memoizing the computed
period with `useMemo(..., [days])` so the fetch path only changes when the
user actually changes the period selector. Fixed in commit `5551a35`;
regression-tested by `tests/e2e/browser_e2e.mjs` and
`frontend/e2e/smoke.spec.ts`, both of which assert the period selector
settles to a single fetch with no error state.

## Adversarial coverage exercised this pass (no findings — confirms existing defenses hold)

These were tested by making the attack actually run against real code, not
assumed correct from reading it. All passed on the areas below; where a test
is new this pass, that's noted — where it pre-existed, that's noted too, so
this list also serves as an index of what's actually covered.

- **JWT algorithm confusion** (`tests/test_oidc.py`, new this pass):
  `alg: none` with an empty signature, and the classic RS256→HS256
  confusion attack (signing with the server's own public key used as an
  HMAC secret) are both rejected. `OIDCVerifier` pins `algorithms=("RS256",
  "ES256")`, which PyJWT enforces before any signature check runs.
- **Tenant isolation / RLS**, pre-existing plus new this pass:
  `tests/test_tenant_isolation_postgres.py` (database-layer, real
  PostgreSQL with the real restricted `helpdesk_app` role: no-context
  sessions see nothing, cross-tenant lookups by primary key return nothing,
  forged-tenant inserts are rejected by the `WITH CHECK` clause) and
  `tests/test_auth_tenant_isolation_api_postgres.py` (same guarantees
  through real HTTP requests with real OIDC tokens: cross-tenant device
  reads/ticket writes 404, not 403 — never confirming existence). New this
  pass: `tests/test_adversarial_security.py`'s
  `test_cross_tenant_action_decision_is_not_found` and
  `test_device_cannot_claim_a_job_belonging_to_another_tenant` close the
  same gap for actions/decisions and job claiming specifically, which
  nothing previously exercised end-to-end.
- **Approval-workflow bypass** (new this pass, `test_adversarial_security.py`):
  re-approving an already-approved action, denying an already-approved
  action, approving an already-denied action, a viewer role attempting a
  decision, deciding a nonexistent action, and cross-tenant decision
  forgery are all rejected (409/403/404 as appropriate). All were already
  correctly guarded by `orchestrator.py`'s state checks and `require_roles`
  — these tests newly prove it at the HTTP layer.
- **Signed-job forgery, replay, and theft** (new this pass,
  `test_adversarial_security.py`): a stale claim token from a superseded
  attempt (simulating what `lease_reaper` produces after a crashed agent)
  cannot submit a result once a fresh claim has superseded it; an expired
  claim lease is rejected at result-submission time, not just at
  re-claim time; a garbage claim token is rejected; a device cannot claim
  a job assigned to a *different* device even within the same tenant
  (`Action.device_id` guard); a device cannot claim a job across tenants
  even when its own path/credentials are otherwise valid (both the
  `require_agent` hash-binding check and the tenant guard independently
  block it); and a claim race with two different idempotency keys leaves
  only the first write standing. All of this was already correctly
  implemented in `api.py`'s `claim_job`/`report_job_result` — these tests
  are new proof, not new code.
- **Prompt injection into AI diagnosis** (new this pass,
  `test_adversarial_security.py::test_injected_incident_evidence_never_becomes_an_executable_instruction`):
  classic injection phrasing ("IGNORE ALL PREVIOUS INSTRUCTIONS...") planted
  directly in device-controlled inventory telemetry (the actual
  attacker-reachable input surface, as opposed to a fabricated LLM
  response) never produces a suggested skill, and — the invariant that
  actually matters — no `Action` is ever auto-created regardless of what a
  diagnosis says. Complements the pre-existing
  `test_ai_provider.py::test_hallucinated_or_injected_skill_id_is_rejected_not_passed_through`,
  which proves the same allowlist boundary starting from a compromised/
  malicious LLM response instead.
- **SSRF**: see the Fixed section above; `EnvironmentSecretsProvider`'s
  namespace restriction (only `HELPDESK_WEBHOOK_SECRET_*` env vars are
  readable, confirmed against an out-of-namespace name like
  `AWS_SECRET_ACCESS_KEY`) was already tested and re-confirmed.
- **Secret/configuration validation**: `Settings.validate_security()` is
  exercised by `tests/test_config.py` for every individual production-mode
  requirement (insecure header auth off, dev login off, OIDC fully
  configured, non-default app-role password) and confirmed to fail closed;
  `.env` is gitignored and has never been committed to this repository's
  history (verified directly against `git log --all -- .env`, empty); `.env.example`
  contains only placeholder values; CI's `security` job runs `gitleaks`
  against full history on every push (currently green).

## Trust-chain integrity (unchanged this pass, re-verified)

The core safety invariant this project is built around —
`Observe → Detect → Correlate → Ticket → Structured action proposal → Policy
→ Independent approval when required → Device-bound job → Authenticated
allowlisted agent executor → Verify → Roll back/escalate → Audit` — was not
weakened anywhere in this pass. Specifically re-confirmed:

- No new code path executes an arbitrary shell/PowerShell command,
  `eval`/`exec`, or unrestricted subprocess. `service.restart` remains the
  only mutating executor, still via a fixed `systemctl` argument vector.
- AI diagnosis remains strictly advisory: `diagnose_with_fallback` never
  creates an `Action`, confirmed again by the new prompt-injection test
  above.
- Every mutating action still passes through `PolicyEngine` before becoming
  a queued job; medium/high-risk skills still require independent approval
  (self-approval rejected, confirmed again this pass).
- Job envelopes remain signed (Ed25519), versioned, and verified by
  `agent_common.signing.verify_envelope` before an agent's executor ever
  sees them; the new adversarial tests strengthen confidence in the
  server-side half of this (claim-token/lease guards) that the existing
  pure-function envelope tests didn't reach.
- Audit events remain append-only and hash-chained; `retention_worker.py`
  still deliberately never touches `audit_events`.

## Residual risk, deliberately deferred (not this pass's scope, not hidden)

These are known, documented gaps — not oversights discovered and left
unfixed. Each has an explicit reason in `docs/IMPLEMENTATION_PLAN.md` and is
repeated here for a security reader who won't necessarily read that file:

- **mTLS** is not implemented (evaluated, deferred — see Milestone 3's
  notes). Endpoint identity today is a bearer device credential plus
  signed job envelopes, not certificate-based transport identity.
- **No key-rotation story for job-envelope signing.** One signing key
  version exists; rotating it requires every already-enrolled agent to
  clear its pinned key and re-pin.
- **No cryptographic signature on skill manifests** — integrity-hash only
  (tamper-evident against direct database modification, not an
  independently verifiable signature chain).
- **The rate limiter (`helpdesktool/hardening.py`) is single-process,
  in-memory** — a real, complete guarantee for this project's default
  single-API-process `compose.yaml` topology, not for a horizontally
  scaled multi-replica deployment, which needs a shared store instead.
- **SSO/SCIM, approval quorum (N-of-M), policy-as-code, and immutable
  audit export/legal-hold** are not built (Milestone 10, unstarted) — real
  enterprise-hardening scope, not required for this MVP's Definition of
  Done.
- **No independent third-party penetration test or dependency fuzzing**
  has been performed. `pip-audit`/`npm audit`/`trivy` (dependency and
  container image CVE scanning) and `gitleaks` (secret scanning) run in CI
  on every push and are currently clean, but these are automated scanners,
  not a human adversarial engagement.

## What this review did not (and could not) do

- No live testing against a real, internet-reachable deployment — this
  environment has no such deployment to test against.
- No fuzzing of request bodies/headers beyond the specific adversarial
  cases above.
- No load/stress testing under sustained adversarial traffic (the rate
  limiter's behavior under real concurrent load from many distinct IPs is
  untested here — its logic is unit-tested, not load-tested).
- No review of a real OIDC provider's actual token issuance behavior — see
  `docs/RELEASE_READINESS.md`'s BLOCKED-EXTERNAL items for what a human
  must verify against a real Auth0/Okta/Keycloak/Cognito tenant before
  production go-live.
