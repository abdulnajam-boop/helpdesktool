from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from .rls import APP_ROLE


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="HELPDESK_", extra="ignore"
    )

    database_url: str = "postgresql+psycopg://helpdesk:helpdesk@localhost:5432/helpdesk"
    app_role_password: str = "change-me-before-use"
    bootstrap_token: str = "change-me-before-use"
    job_claim_secret: str = "change-me-before-use"
    job_signing_seed: str = "change-me-before-use"
    environment: str = "development"
    allow_insecure_header_auth: bool = True
    development_login_enabled: bool = True
    development_session_secret: str = "change-me-before-use"
    development_session_minutes: int = 480
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    low_disk_threshold_percent: float = 85.0
    incident_correlation_hours: int = 24
    service_allowlist: str = ""
    webhook_allow_http: bool = False
    webhook_timeout_seconds: float = 10.0
    webhook_max_attempts: int = 8
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    lease_reaper_max_attempts: int = 3
    lease_reaper_poll_seconds: float = 15.0
    # All empty by default on purpose: the platform must fully function with
    # no AI provider configured at all (helpdesktool.ai falls back to a
    # deterministic, non-network summary — see ai_configured below and
    # helpdesktool/ai/provider.py's module docstring for the full trust
    # model). Any OpenAI-compatible endpoint works; nothing here is tied to
    # a specific vendor.
    ai_provider_base_url: str = ""
    ai_provider_api_key: str = ""
    ai_provider_model: str = ""
    ai_timeout_seconds: float = 20.0
    ai_max_retries: int = 1

    @property
    def ai_configured(self) -> bool:
        return bool(
            self.ai_provider_base_url
            and self.ai_provider_api_key
            and self.ai_provider_model
        )

    @property
    def allowed_services(self) -> frozenset[str]:
        return frozenset(
            item.strip() for item in self.service_allowlist.split(",") if item.strip()
        )

    @property
    def allowed_cors_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url)

    @property
    def runtime_database_url(self) -> str:
        """The connection the API and webhook worker use at runtime.

        This is deliberately *not* ``database_url`` for a PostgreSQL target:
        that URL's role is the schema owner, which PostgreSQL always exempts
        from row-level security (see ``helpdesktool.rls``). The application
        must connect as the restricted, non-superuser ``helpdesk_app`` role —
        migration 0005 creates it with this same ``app_role_password`` — so
        that RLS policies are actually enforced against live request
        traffic. For any non-PostgreSQL URL (e.g. SQLite in tests), this is
        just ``database_url`` unchanged, since RLS/role separation is a
        PostgreSQL-only concept.
        """
        url = make_url(self.database_url)
        if url.get_backend_name() != "postgresql":
            return self.database_url
        return url.set(
            username=APP_ROLE, password=self.app_role_password
        ).render_as_string(hide_password=False)

    def validate_security(self) -> None:
        if self.environment != "development" and self.allow_insecure_header_auth:
            raise RuntimeError(
                "insecure X-Tenant-ID/X-User-ID authentication is development-only"
            )
        if self.environment != "development" and self.development_login_enabled:
            raise RuntimeError("development browser login is development-only")
        if self.environment != "development" and not self.oidc_configured:
            raise RuntimeError(
                "OIDC issuer, audience, and JWKS URL must all be configured "
                "outside development — there is no other way to authenticate "
                "a human user in this environment"
            )
        if self.environment != "development" and "change-me-before-use" in {
            self.bootstrap_token,
            self.job_claim_secret,
            self.job_signing_seed,
            self.development_session_secret,
            self.app_role_password,
        }:
            raise RuntimeError(
                "bootstrap, session, job claim, job signing, and app role "
                "secrets must be changed"
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_security()
    return settings
