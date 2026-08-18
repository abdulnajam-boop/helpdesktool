from datetime import UTC, datetime

import pytest

from helpdesktool.development_auth import (
    InvalidDevelopmentSession,
    issue_session,
    verify_session,
)


def test_development_session_is_signed_and_tenant_bound():
    token = issue_session("user-1", "tenant-1", "test-secret", 10)
    claims = verify_session(token, "test-secret")
    assert claims["sub"] == "user-1"
    assert claims["tenant"] == "tenant-1"
    assert claims["exp"] > int(datetime.now(UTC).timestamp())
    with pytest.raises(InvalidDevelopmentSession):
        verify_session(token, "different-secret")


def test_expired_development_session_is_rejected():
    token = issue_session("user-1", "tenant-1", "test-secret", -1)
    with pytest.raises(InvalidDevelopmentSession, match="expired"):
        verify_session(token, "test-secret")
