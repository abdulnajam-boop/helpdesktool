import pytest

from helpdesktool.config import Settings


def test_production_rejects_development_header_authentication():
    settings = Settings(
        environment="production",
        allow_insecure_header_auth=True,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
    )
    with pytest.raises(RuntimeError, match="development-only"):
        settings.validate_security()


def test_production_accepts_disabled_header_auth_with_configured_secrets():
    settings = Settings(
        environment="production",
        allow_insecure_header_auth=False,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
    )
    settings.validate_security()
