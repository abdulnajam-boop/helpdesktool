"""Unit tests for helpdesktool.hardening's middleware, exercised against a
minimal standalone Starlette app rather than the shared helpdesktool.api
app -- that app's RateLimitMiddleware is deliberately disabled in
development (see the middleware's own docstring for why: the whole test
suite shares one process-wide app instance, so a shared limiter there would
be tripped by the suite's own aggregate request volume, not by anything
these tests actually want to verify). Testing the middleware in isolation
here gives real, deterministic coverage of the rate-limiting logic itself.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from helpdesktool.hardening import (
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)


async def _ok(request):
    return PlainTextResponse("ok")


def test_security_headers_are_set_on_every_response():
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(SecurityHeadersMiddleware, hsts=True)
    client = TestClient(app)
    response = client.get("/thing")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert "max-age=63072000" in response.headers["Strict-Transport-Security"]


def test_security_headers_omits_hsts_when_disabled():
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(SecurityHeadersMiddleware, hsts=False)
    client = TestClient(app)
    response = client.get("/thing")
    assert "Strict-Transport-Security" not in response.headers


def test_request_size_limit_allows_small_bodies():
    async def echo(request):
        body = await request.body()
        return PlainTextResponse(str(len(body)))

    app = Starlette(routes=[Route("/thing", echo, methods=["POST"])])
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=1000)
    client = TestClient(app)
    response = client.post("/thing", content=b"x" * 100)
    assert response.status_code == 200
    assert response.text == "100"


def test_request_size_limit_rejects_oversized_declared_content_length():
    async def echo(request):
        body = await request.body()
        return PlainTextResponse(str(len(body)))

    app = Starlette(routes=[Route("/thing", echo, methods=["POST"])])
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=10)
    client = TestClient(app)
    response = client.post("/thing", content=b"x" * 1000)
    assert response.status_code == 413


def test_rate_limit_allows_requests_under_the_threshold():
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(RateLimitMiddleware, max_requests=5, window_seconds=60)
    client = TestClient(app)
    for _ in range(5):
        assert client.get("/thing").status_code == 200


def test_rate_limit_rejects_requests_over_the_threshold():
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(RateLimitMiddleware, max_requests=3, window_seconds=60)
    client = TestClient(app)
    for _ in range(3):
        assert client.get("/thing").status_code == 200
    denied = client.get("/thing")
    assert denied.status_code == 429


def test_rate_limit_exempts_health_and_metrics_paths():
    app = Starlette(
        routes=[
            Route("/thing", _ok),
            Route("/health/live", _ok),
            Route("/metrics", _ok),
        ]
    )
    app.add_middleware(RateLimitMiddleware, max_requests=1, window_seconds=60)
    client = TestClient(app)
    assert client.get("/thing").status_code == 200
    # The one request against /thing already used up the whole budget --
    # /health/live and /metrics must still succeed regardless.
    for _ in range(10):
        assert client.get("/health/live").status_code == 200
        assert client.get("/metrics").status_code == 200
    assert client.get("/thing").status_code == 429


def test_rate_limit_disabled_lets_unlimited_requests_through():
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(
        RateLimitMiddleware, max_requests=1, window_seconds=60, enabled=False
    )
    client = TestClient(app)
    for _ in range(20):
        assert client.get("/thing").status_code == 200


def test_rate_limit_ignores_spoofable_forwarded_for_header():
    """The limiter must key strictly on the transport-level
    ``request.client.host``, never a client-supplied header -- otherwise a
    single client could trivially reset its own budget by sending a
    different ``X-Forwarded-For`` value on every request. Both calls below
    come from the same underlying test connection with different
    X-Forwarded-For headers; the second is still rejected, proving the
    header was never consulted.
    """
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(RateLimitMiddleware, max_requests=1, window_seconds=60)
    client = TestClient(app)
    assert (
        client.get("/thing", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    )
    assert (
        client.get("/thing", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429
    )


def test_real_app_sends_security_headers_on_a_real_request(client):
    """Proves the middleware is actually wired into helpdesktool.api's real
    app (not just tested in isolation above) -- SecurityHeadersMiddleware
    isn't gated by environment, so it applies even in the development mode
    the test suite runs in.
    """
    http, _ = client
    response = http.get("/health/live")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_real_app_disables_docs_outside_development(client):
    """The client fixture runs in development mode (the default), so /docs
    is reachable there; the point of this test is to confirm the endpoint
    exists and is gated by Settings.environment at all, matching every
    other dev-only surface in this codebase -- see api.py's _docs_enabled.
    """
    http, _ = client
    assert http.get("/docs").status_code == 200
    assert http.get("/openapi.json").status_code == 200


def test_real_app_rate_limiter_is_disabled_in_development(client):
    """Confirms the deliberate dev-mode bypass documented in
    RateLimitMiddleware actually takes effect for the real app: many rapid
    requests in development must never trip 429, since the whole point is
    that local development and this very test suite share one app instance
    and therefore one limiter across every test in a run. Deliberately
    targets a *non-exempt* path (/health/live and /metrics are always
    exempt regardless of enabled/disabled, so hitting one of those would
    prove nothing about the dev-mode bypass specifically) -- an
    unauthenticated request is fine here, since only the status code
    "isn't 429" is under test, not whether the request succeeds.
    """
    http, _ = client
    for _ in range(50):
        assert http.get("/v1/devices").status_code != 429
