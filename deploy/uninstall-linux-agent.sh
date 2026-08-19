#!/usr/bin/env bash
# Removes the Helpdesktool Linux endpoint agent installed by
# install-linux-agent.sh: stops and disables the service, removes the
# systemd unit, the installed package, and (unless --keep-config is passed)
# the local config/credentials/execution journal.
#
# This does NOT revoke the device's credential or enrollment on the
# control plane -- do that first from the operator console (Devices ->
# revoke) or POST /v1/devices/{id}/revoke, so a stale credential can't be
# reused, before or after running this script.
#
# Usage: sudo ./uninstall-linux-agent.sh [--keep-config]
set -euo pipefail

SERVICE_USER="helpdesk-agent"
INSTALL_DIR="/opt/helpdesktool"
CONFIG_DIR="/etc/helpdesktool"
UNIT_NAME="helpdesk-linux-agent.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"

KEEP_CONFIG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-config) KEEP_CONFIG=1; shift ;;
    -h|--help) echo "usage: $0 [--keep-config]"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "this uninstaller must be run as root" >&2
  exit 1
fi

if systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1; then
  echo "==> Stopping and disabling $UNIT_NAME"
  systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
fi

if [[ -f "$UNIT_PATH" ]]; then
  echo "==> Removing systemd unit"
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
fi

echo "==> Removing installed package at $INSTALL_DIR"
rm -rf "$INSTALL_DIR"

if [[ -n "$KEEP_CONFIG" ]]; then
  echo "==> Keeping $CONFIG_DIR (--keep-config passed)"
else
  echo "==> Removing $CONFIG_DIR (credentials, execution journal)"
  rm -rf "$CONFIG_DIR"
fi

if id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "==> Removing service account $SERVICE_USER"
  userdel "$SERVICE_USER" 2>/dev/null || true
fi

echo "==> Done. Remember to revoke this device's credential on the control plane if you haven't already."
