# Windows endpoint agent deployment

Mirrors `deploy/helpdesk-linux-agent.service`'s role for the Linux agent: how
to install `windows_agent` as a real, boot-persistent, auto-restarting
Windows Service rather than a foreground console process.

## Prerequisites

```powershell
python -m pip install helpdesktool[windows]
```

This installs `psutil` (inventory collectors) and `pywin32` (Service Control
Manager access for the `service.restart` remediation skill and the service
wrapper itself — see `windows_agent/win32_service_manager.py`). No shell,
`sc.exe`, or PowerShell is ever spawned by the agent to control a service;
it talks to SCM directly through the Win32 API.

## Enrollment

Same two options the control plane supports for Linux, from an elevated
prompt:

```powershell
# Admin-mediated (requires an authenticated admin/owner session token —
# same flow as helpdesk-linux-agent's first run):
helpdesk-windows-agent --config C:\ProgramData\helpdesktool\agent.json --once

# Or self-enrollment with a one-time token an admin generated via
# POST /v1/devices/enrollment-tokens (see docs/IMPLEMENTATION_PLAN.md
# Milestone 3) — write agent.json by hand with device_id/agent_token left
# unset, tenant_id/user_id/external_id/server_url filled in, then enroll via
# POST /v1/devices/enroll-with-token before first run, or extend
# windows_agent.agent.WindowsAgent.enroll() to call it directly.
```

The config file (`C:\ProgramData\helpdesktool\agent.json` by default —
override with `--config`) has the same shape as the Linux agent's, with
`"os"` handled automatically as `"windows"` by `windows_agent.client`.
`allowed_services` must list the exact Windows service names (as shown by
`Get-Service`, e.g. `"Spooler"`) this device is allowed to restart — the
same allowlist-enforcement model as the Linux agent's `systemctl` unit
names.

**Credential protection**: unlike POSIX file permissions, NTFS ACLs are not
set by the agent itself (`os.chmod` is a documented no-op on Windows — see
`windows_agent/config.py`). Run the service as a dedicated, low-privilege
service account (not `LocalSystem`, not an interactive admin account) and
restrict `C:\ProgramData\helpdesktool`'s ACL to that account plus
Administrators:

```powershell
icacls C:\ProgramData\helpdesktool /inheritance:r
icacls C:\ProgramData\helpdesktool /grant "NT SERVICE\HelpdeskWindowsAgent:(OI)(CI)F"
icacls C:\ProgramData\helpdesktool /grant "BUILTIN\Administrators:(OI)(CI)F"
```

## Install as a Windows Service

From an elevated prompt:

```powershell
helpdesk-windows-agent-service --startup auto install
helpdesk-windows-agent-service start
```

This registers `HelpdeskWindowsAgent` ("Helpdesktool Endpoint Agent") via
`win32serviceutil.ServiceFramework` (`windows_agent/service.py`) — visible in
`services.msc`, responds to a clean SCM stop request instead of being
killed, and runs the same heartbeat/inventory/job loop as
`helpdesk-windows-agent --config ...` in the foreground.

Configure automatic restart on failure (the SCM-native equivalent of the
Linux unit's `Restart=on-failure` / `RestartSec=10`):

```powershell
sc.exe failure HelpdeskWindowsAgent reset=86400 actions=restart/10000/restart/10000/restart/10000
```

## Uninstall

```powershell
helpdesk-windows-agent-service stop
helpdesk-windows-agent-service remove
```

## Known limitation

The agent's local replay file (`agent.processed.json`, next to `agent.json`)
guards against re-processing already-*completed* actions but — same as the
Linux agent — does not yet protect against a crash between "restart
succeeded" and "result reported" to the control plane. The server-side
`helpdesk-lease-reaper` (Milestone 3) recovers the *job* in that case
(requeues or escalates it after the lease expires), but the agent itself
does not yet have a durable execution journal. See
`docs/IMPLEMENTATION_PLAN.md` Milestone 3.
