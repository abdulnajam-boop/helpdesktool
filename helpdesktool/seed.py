"""Idempotent development demo-data seed command."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from .config import get_settings
from .database import SessionLocal
from .db_models import Action, Device, DeviceInventory, Tenant, Ticket, User
from .incidents import detect_inventory_incidents
from .persistence import SqlAuditLog

DEMO_USERS = (
    ("owner@acme.local", "owner"),
    ("admin@acme.local", "admin"),
    ("operator@acme.local", "operator"),
    ("viewer@acme.local", "viewer"),
)


def seed() -> None:
    settings = get_settings()
    if settings.environment != "development":
        raise RuntimeError("demo seed is development-only")
    with SessionLocal() as session:
        tenant = session.scalar(select(Tenant).where(Tenant.name == "Acme IT"))
        if tenant is None:
            tenant = Tenant(name="Acme IT")
            session.add(tenant)
            session.flush()
        users: dict[str, User] = {}
        for email, role in DEMO_USERS:
            user = session.scalar(
                select(User).where(User.tenant_id == tenant.id, User.email == email)
            )
            if user is None:
                user = User(tenant_id=tenant.id, email=email, role=role, active=True)
                session.add(user)
                session.flush()
            users[role] = user
        now = datetime.now(UTC)
        device_specs = (
            ("web-prod-01", "linux", now - timedelta(seconds=30)),
            ("db-prod-01", "linux", now - timedelta(minutes=2)),
            ("employee-laptop-01", "windows", now - timedelta(days=2)),
        )
        devices: dict[str, Device] = {}
        for hostname, os_name, last_seen in device_specs:
            device = session.scalar(
                select(Device).where(
                    Device.tenant_id == tenant.id, Device.external_id == hostname
                )
            )
            if device is None:
                device = Device(
                    tenant_id=tenant.id,
                    external_id=hostname,
                    hostname=hostname,
                    os=os_name,
                    agent_key_hash=hashlib.sha256(
                        f"demo:{hostname}".encode()
                    ).hexdigest(),
                    last_seen_at=last_seen,
                )
                session.add(device)
                session.flush()
            devices[hostname] = device
        web = devices["web-prod-01"]
        existing_inventory = session.scalar(
            select(DeviceInventory).where(DeviceInventory.device_id == web.id)
        )
        if existing_inventory is None:
            payload = _inventory_payload(91.0)
            session.add(
                DeviceInventory(
                    tenant_id=tenant.id,
                    device_id=web.id,
                    collected_at=now,
                    payload=payload,
                )
            )
            detect_inventory_incidents(
                session, tenant.id, web.id, payload, now, settings
            )
        if (
            session.scalar(
                select(Ticket).where(
                    Ticket.tenant_id == tenant.id,
                    Ticket.title == "Database backup verification",
                )
            )
            is None
        ):
            session.add(
                Ticket(
                    tenant_id=tenant.id,
                    device_id=devices["db-prod-01"].id,
                    title="Database backup verification",
                    description="Confirm the latest production backup completed and is restorable.",
                    status="in_progress",
                    priority="normal",
                    created_by=users["operator"].id,
                )
            )
        if (
            session.scalar(
                select(Action).where(
                    Action.tenant_id == tenant.id, Action.device_id == web.id
                )
            )
            is None
        ):
            action = Action(
                id="11111111-1111-4111-8111-111111111111",
                tenant_id=tenant.id,
                device_id=web.id,
                ticket_id=None,
                skill_id="service.restart",
                requested_by=users["operator"].id,
                parameters={"service": "nginx"},
                device_os="linux",
                risk="medium",
                status="pending_approval",
                approved_by=None,
                attempt=0,
            )
            session.add(action)
            SqlAuditLog(session).append(
                tenant_id=tenant.id,
                correlation_id=action.id,
                event_type="approval.required",
                actor_id=users["operator"].id,
                details={
                    "device_id": web.id,
                    "skill_id": action.skill_id,
                    "risk": action.risk,
                },
            )
        session.commit()
        print(f"Seeded development tenant {tenant.name} ({tenant.id})")


def _inventory_payload(used_percent: float) -> dict[str, object]:
    total = 100 * 1024**3
    return {
        "hostname": "web-prod-01",
        "cpu": {"logical_cpus": 4, "utilization_percent": 24.5},
        "memory": {"total_bytes": 8 * 1024**3, "available_bytes": 3 * 1024**3},
        "filesystems": [
            {
                "device": "/dev/vda1",
                "mountpoint": "/",
                "filesystem": "ext4",
                "total_bytes": total,
                "free_bytes": int(total * (100 - used_percent) / 100),
            }
        ],
        "services": [{"service": "nginx", "active": "active"}],
    }


if __name__ == "__main__":
    seed()
