# Helpdesktool SaaS MVP manual QA

This checklist tests the browser product and deterministic safety path without filling a real disk or granting the control plane remote-shell access.

## 1. Configure and start

1. From the repository root run `cp .env.example .env`.
2. Replace every `replace-with-...` password and secret in `.env`. Keep `HELPDESK_ENVIRONMENT=development` and `HELPDESK_DEVELOPMENT_LOGIN_ENABLED=true` for this local test only.
3. Run the one canonical startup command: `docker compose up --build`.
4. Expect `db` to become healthy, `migrate` and `seed` to exit successfully, and `api`, `frontend`, and `webhook-worker` to remain running.
5. Open `http://localhost:8000/health/live`; expect `{"status":"ok"}`.
6. Open `http://localhost:8000/health/ready`; expect `{"status":"ready"}`.
7. Open `http://localhost:3000`; expect the Helpdesktool development login page.

## 2. Login and role behavior

1. Select `admin@acme.local`. Expect the application shell, Acme IT header, Admin badge, and all nine navigation entries.
2. Sign out and select `viewer@acme.local`. Expect all read pages to load, but no ticket/action/integration creation or approval controls.
3. A direct Viewer POST, PATCH, or DELETE request must return `403`; hiding a button is not the security boundary.
4. Sign in again as `admin@acme.local`.

## 3. Dashboard

1. Expect seven API-backed cards: total, online, and offline devices; open tickets; open incidents; pending approvals; and failed actions.
2. Expect recent incidents, tickets, and actions populated from the seed.
3. Open rows from each recent table and confirm their detail pages load.

## 4. Devices and deterministic low-disk simulation

1. Open **Devices**. Expect `web-prod-01`, `db-prod-01`, and `employee-laptop-01`, including OS, connection status, last-seen time, and open-incident count.
2. Search for `web-prod` and open `web-prod-01`.
3. Confirm identity, latest heartbeat, inventory, incident, ticket, action, and audit sections contain data.
4. In **Simulated disk use**, enter `96` and select **Submit telemetry**. Expect the existing `/` low-disk incident occurrence count to increase and severity to become critical.
5. Submit `40`. Expect the incident and its linked ticket to become resolved because verified telemetry is below the configured threshold.
6. Submit `96` again. Expect the same correlation key to reopen the same incident, not create an unlimited duplicate.
7. Open the incident. Confirm filesystem, used percentage, free and total bytes, threshold, observation time, linked ticket, actions, and timeline.

This simulator is development-only, accepts structured numeric telemetry, is restricted to authorized roles and Linux devices, and never executes a command.

## 5. Tickets

1. Open **Tickets** and select **Create ticket**.
2. Enter a summary/description, priority, and device; save it and expect it in the list.
3. Open the ticket. Change status and priority with the detail controls; expect the page and audit timeline to update.
4. For the seeded low-disk ticket, confirm the linked incident and remediation-action sections.
5. Log in as Viewer and confirm update controls are absent and backend writes return `403`.

## 6. Incidents

1. Open **Incidents** and filter by `low disk`.
2. Confirm severity, status, occurrences, first/last observations, device, structured evidence, linked ticket, linked actions, and timeline.
3. Repeat the simulator steps above and confirm correlation, resolution, and reopening transitions appear in Audit.

## 7. Actions and approvals

1. Open **Actions**. Expect skill, device, risk, status, and creation time.
2. Open the seeded action. Confirm structured parameters, requester, risk, approval history, execution/verification/rollback results, and timeline.
3. As Admin, open **Approvals**, review the seeded request, and select Approve or Deny. Confirm the dialog before proceeding.
4. If approved, expect `queued`, not locally executed. The browser and control plane cannot run `systemctl`.
5. Create another action from **Actions** using `helpdesk-demo.service`. Policy must evaluate it and require independent approval. A requester attempting to approve their own request must receive `403`.

## 8. Optional live Linux agent execution

Use a disposable Linux VM or container with a harmless demo systemd unit.

1. Enroll it using an Owner/Admin identity and save the returned one-time agent token.
2. Configure `agent.example.json` with the returned device ID/token and allow only `helpdesk-demo.service`.
3. Request and independently approve `service.restart` for that device.
4. Run `helpdesk-linux-agent --config ~/.config/helpdesktool/agent.json --once` as an unprivileged user with narrowly scoped PolicyKit permission.
5. Expect the agent alone to claim the device-bound lease, validate the allowlist and exact parameters, invoke a fixed `systemctl` argv without `shell=True`, verify state, report the result, and record rollback/escalation if verification fails.
6. Confirm the Action and Audit pages show claim, execution result, verification, and final state.

## 9. Audit

1. Open **Audit**. Expect timestamp, actor, event, correlated resource, and structured details.
2. Filter by exact event type `incident.updated`.
3. Clear it and paste an incident, ticket, device, or action ID into the correlation filter.
4. Confirm only the current tenant's hash-chained events are returned.

## 10. Integrations

1. Open **Integrations** as Admin.
2. Create an HTTPS webhook with an `env:HELPDESK_WEBHOOK_SECRET_*` reference. Expect it in the list without any secret value displayed.
3. Credential-bearing, loopback/private, and plain HTTP URLs must be rejected by default.
4. Inspect recent delivery status.
5. Disable the subscription, confirm the dialog, and expect its badge to change to disabled.
6. Confirm Viewer can inspect but cannot create or disable subscriptions.

## 11. Settings

1. Open **Settings**. Confirm Acme IT, environment/development status, four users and roles, low-disk threshold, service allowlist, and supported domain events.
2. Confirm no database password, session secret, agent token, webhook signing secret, or claim token is displayed.

## 12. Persistence, shutdown, and reset

1. Run `docker compose down`, then `docker compose up --build`.
2. Log in and expect prior ticket edits plus the idempotent demo dataset; the seed must not multiply users, devices, tickets, incidents, or the seeded action uncontrollably.
3. For an intentional clean reset only, run `docker compose down -v` followed by `docker compose up --build`.
