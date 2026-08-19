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
        development_login_enabled=False,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
        job_signing_seed="configured-job-signing-seed",
        development_session_secret="configured-session-secret",
        app_role_password="configured-app-role-password",
        oidc_issuer="https://idp.example.com/",
        oidc_audience="https://api.example.com",
        oidc_jwks_url="https://idp.example.com/.well-known/jwks.json",
    )
    settings.validate_security()


def test_production_rejects_default_app_role_password():
    settings = Settings(
        environment="production",
        allow_insecure_header_auth=False,
        development_login_enabled=False,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
        development_session_secret="configured-session-secret",
        oidc_issuer="https://idp.example.com/",
        oidc_audience="https://api.example.com",
        oidc_jwks_url="https://idp.example.com/.well-known/jwks.json",
    )
    with pytest.raises(RuntimeError, match="app role"):
        settings.validate_security()


def test_production_rejects_missing_oidc_configuration():
    settings = Settings(
        environment="production",
        allow_insecure_header_auth=False,
        development_login_enabled=False,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
        development_session_secret="configured-session-secret",
    )
    with pytest.raises(RuntimeError, match="OIDC"):
        settings.validate_security()


def test_production_rejects_partially_configured_oidc():
    settings = Settings(
        environment="production",
        allow_insecure_header_auth=False,
        development_login_enabled=False,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
        development_session_secret="configured-session-secret",
        oidc_issuer="https://idp.example.com/",
        oidc_audience="",
        oidc_jwks_url="https://idp.example.com/.well-known/jwks.json",
    )
    with pytest.raises(RuntimeError, match="OIDC"):
        settings.validate_security()


def test_runtime_database_url_swaps_to_restricted_app_role_for_postgresql():
    settings = Settings(
        database_url="postgresql+psycopg://helpdesk:helpdesk-superuser-pw@db:5432/helpdesk",
        app_role_password="app-role-secret",
    )
    runtime_url = settings.runtime_database_url
    assert "helpdesk_app" in runtime_url
    assert "app-role-secret" in runtime_url
    assert "helpdesk-superuser-pw" not in runtime_url
    assert runtime_url.startswith("postgresql+psycopg://")
    assert "@db:5432/helpdesk" in runtime_url


def test_runtime_database_url_unchanged_for_non_postgresql():
    settings = Settings(database_url="sqlite:///./test.db")
    assert settings.runtime_database_url == settings.database_url


def test_production_rejects_development_browser_login():
    settings = Settings(
        environment="production",
        allow_insecure_header_auth=False,
        development_login_enabled=True,
        bootstrap_token="configured-bootstrap",
        job_claim_secret="configured-job-secret",
        development_session_secret="configured-session-secret",
    )
    with pytest.raises(RuntimeError, match="development browser login"):
        settings.validate_security()
