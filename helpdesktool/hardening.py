"""Security-hardening HTTP middleware: response headers, request-size
limits, and a basic per-client rate limiter.

This is a JSON API (no first-party HTML beyond FastAPI's own ``/docs``,
which ``api.py`` disables outside development), so the headers here are
tuned for that: a restrictive Content-Security-Policy rather than one built
for serving a page. The frontend SPA's own security headers are set by its
nginx config (``frontend/nginx.conf``), not here.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_EXEMPT_PATHS = frozenset({"/health/live", "/health/ready", "/metrics"})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, *, hsts: bool) -> None:
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        if self.hsts:
            # Only set outside development -- HSTS pins the browser to
            # HTTPS for max-age seconds, which actively breaks plain-HTTP
            # local development if sent there.
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects a request whose declared ``Content-Length`` exceeds
    ``max_bytes`` before the body is ever read — bounds the memory a single
    request can force the process to allocate. Requests without a
    ``Content-Length`` (chunked transfer) pass through unexamined here;
    this API's real clients (the browser SPA, the endpoint agents) always
    send one, so this catches the realistic case without adding a
    streaming-enforcement layer for a transfer mode nothing legitimate uses.
    """

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                declared = None
            if declared is not None and declared > self.max_bytes:
                return Response(
                    status_code=413, content=b'{"detail":"request too large"}'
                )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """A basic per-client-IP sliding-window rate limiter, enforced in
    process memory.

    Known limitation, stated plainly: in-memory state means this only
    limits per process. This platform's default deployment topology
    (``compose.yaml``) runs a single API process, so that's a real,
    complete guarantee here — but a multi-replica production deployment
    needs a shared store (Redis, or an API-gateway-level limiter) for a
    consistent limit across replicas. This is an honest starting point for
    that topology, not a claim of distributed correctness it doesn't have.

    ``/health/*`` and ``/metrics`` are exempt (scraped frequently and
    predictably by infrastructure, not user traffic that could abuse them
    the way a real endpoint could).

    ``enabled=False`` (``api.py`` passes this when
    ``Settings.environment == "development"``, the same dev-only
    relaxation pattern as everything else in this codebase) makes every
    request pass straight through with no bookkeeping at all — deliberate,
    not an oversight: it keeps local development and the test suite (which
    shares one process-wide `app` instance, and therefore one shared
    limiter, across every test in a run) from ever being spuriously
    rate-limited by their own aggregate request volume, which has nothing
    to do with what this middleware exists to catch.
    """

    def __init__(
        self,
        app: Any,
        *,
        max_requests: int,
        window_seconds: float,
        enabled: bool = True,
    ) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.enabled = enabled
        self._hits: dict[str, deque[float]] = {}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if (
            not self.enabled
            or request.method == "OPTIONS"
            or request.url.path in _EXEMPT_PATHS
        ):
            return await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = self._hits.setdefault(client_ip, deque())
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        if len(window) >= self.max_requests:
            return Response(
                status_code=429, content=b'{"detail":"rate limit exceeded"}'
            )
        window.append(now)
        if len(self._hits) > 10_000:
            self._prune(now)
        return await call_next(request)

    def _prune(self, now: float) -> None:
        stale = [
            ip
            for ip, window in self._hits.items()
            if not window or now - window[-1] > self.window_seconds * 2
        ]
        for ip in stale:
            del self._hits[ip]
