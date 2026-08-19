#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes the Helpdesktool Windows endpoint agent installed by
  install-windows-agent.ps1: stops and removes the service, the installed
  package, and (unless -KeepConfig is passed) the local config/credentials/
  execution journal.

.DESCRIPTION
  This does NOT revoke the device's credential or enrollment on the
  control plane -- do that first from the operator console (Devices ->
  revoke) or POST /v1/devices/{id}/revoke, so a stale credential can't be
  reused, before or after running this script.

.PARAMETER KeepConfig
  Leave C:\ProgramData\helpdesktool (config, credentials, execution
  journal) in place instead of deleting it.
#>
param(
    [switch]$KeepConfig
)

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\Helpdesktool"
$ConfigDir = "C:\ProgramData\helpdesktool"
$ServiceName = "HelpdeskWindowsAgent"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "==> Stopping and removing $ServiceName"
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path "$InstallDir\venv\Scripts\helpdesk-windows-agent-service.exe") {
        & "$InstallDir\venv\Scripts\helpdesk-windows-agent-service.exe" remove
    } else {
        sc.exe delete $ServiceName | Out-Null
    }
}

if (Test-Path $InstallDir) {
    Write-Host "==> Removing installed package at $InstallDir"
    Remove-Item -Recurse -Force $InstallDir
}

if ($KeepConfig) {
    Write-Host "==> Keeping $ConfigDir (-KeepConfig passed)"
} elseif (Test-Path $ConfigDir) {
    Write-Host "==> Removing $ConfigDir (credentials, execution journal)"
    Remove-Item -Recurse -Force $ConfigDir
}

Write-Host "==> Done. Remember to revoke this device's credential on the control plane if you haven't already."
