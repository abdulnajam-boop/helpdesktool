from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, cast


class ApiError(RuntimeError):
    pass


class ControlPlaneClient:
    def __init__(self, server_url: str, timeout: float = 15.0) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            self.server_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            message = exc.read().decode(errors="replace")[:1000]
            raise ApiError(f"control plane returned {exc.code}: {message}") from exc

    def enroll(
        self, tenant_id: str, user_id: str, external_id: str, hostname: str
    ) -> dict[str, str]:
        return cast(
            dict[str, str],
            self.request(
                "POST",
                "/v1/devices/enroll",
                payload={
                    "external_id": external_id,
                    "hostname": hostname,
                    "os": "windows",
                },
                headers={"X-Tenant-ID": tenant_id, "X-User-ID": user_id},
            ),
        )

    @staticmethod
    def agent_headers(token: str, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {token}"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers
