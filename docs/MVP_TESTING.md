# Helpdesktool SaaS MVP manual test

This checklist validates the deterministic product path without granting the browser or control plane remote-shell access.

## 1. Start a clean stack

1. Run `cp .env.example .env` and replace all placeholder passwords and secrets.
2. Run `docker compose up --build`.
3. Confirm PostgreSQL becomes healthy, `migrate` and `seed` exit successfully, and `api`, `frontend`, and `webhook-worker` remain running.
4. Open `http://localhost:8000/health/live`; expect `{"status":"ok"}`.
5. Open `http://localhost:3000`; expect the Helpdesktool development login page.

## 2. Login and role checks

1. Select `admin@acme.local`.
2. Confirm the Dashboard displays Acme IT data and seven live counters.
3. Sign out and select `viewer@acme.local`.
4. Confirm read pages load. Direct POST/PATCH/DELETE API requests with the viewer session must return `403`; hidden buttons are not the security boundary.
5. Return as the admin.

## 3. Dashboard and resources

1. Confirm three devices: `web-prod-01`, `db-prod-01`, and `employee-laptop-01`.
2. Open `web-prod-01`; inspect its latest CPU, memory, filesystem, service inventory, linked incident, ticket, and action lists.
3. Open Tickets and inspect the automatically generated low-disk ticket.
4. Open Incidents and inspect evidence for `/`: used percentage, free bytes, threshold, device, and observation time.
5. Open Actions and confirm the seeded `service.restart` is `pending approval`.

## 4. Approval safety gate

1. Open Approvals and select Approve only after reviewing device, risk, skill, and parameters.
2. Confirm the dialog before proceeding.
3. Confirm the action transitions to `queued`; the browser does not execute it.
4. A second approval attempt or self-approval must fail according to backend policy.

## 5. Live agent lifecycle

1. Enroll a disposable test device through `POST /v1/devices/enroll` as an owner/admin and save the one-time agent token.
2. Configure `agent.example.json` with that device ID/token and run `helpdesk-linux-agent` as an unprivileged user.
3. Create a structured `service.restart` action for a service listed in `HELPDESK_SERVICE_ALLOWLIST`.
4. Approve it using a different authorized user from the requester.
5. Confirm the agent alone claims the device-bound job, checks its local allowlist, runs fixed `systemctl` argv without `shell=True`, verifies state, and reports structured output.
6. Confirm the action timeline reaches succeeded, failed, or rolled back and Audit records the claim, result, verification, and escalation outcome.

Do not use a production service for this test. A disposable demo service is recommended.

## 6. Low-disk correlation

1. POST authenticated inventory for a disposable device with `total_bytes: 1000`, `free_bytes: 50`, and `mountpoint: /test`.
2. Confirm one low-disk incident and linked ticket appear.
3. POST another observation for the same mountpoint within 24 hours using a new idempotency key.
4. Confirm the same incident ID remains and occurrence count increments; no duplicate ticket is created.
5. Confirm `incident.created` and `incident.updated` appear in Audit and the signed webhook outbox when a matching integration exists.

## 7. Integrations and audit

1. Create an HTTPS webhook using an `env:HELPDESK_WEBHOOK_SECRET_*` reference. Private, loopback, credential-bearing, and plain HTTP URLs must be rejected by default.
2. Disable the webhook and confirm it becomes inactive.
3. Search Audit by event or resource correlation ID through the API query filters.
4. Verify tenant data never appears when using another tenant's valid session.

## 8. Shutdown

Run `docker compose down`. Use `docker compose down -v` only when you intentionally want to destroy the development database.
