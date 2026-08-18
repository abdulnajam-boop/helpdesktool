from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="HELPDESK_", extra="ignore"
    )

    database_url: str = "postgresql+psycopg://helpdesk:helpdesk@localhost:5432/helpdesk"
    bootstrap_token: str = "change-me-before-use"
    job_claim_secret: str = "change-me-before-use"
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

    @property
    def allowed_services(self) -> frozenset[str]:
        return frozenset(
            item.strip() for item in self.service_allowlist.split(",") if item.strip()
        )

    @property
    def allowed_cors_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    def validate_security(self) -> None:
        if self.environment != "development" and self.allow_insecure_header_auth:
            raise RuntimeError(
                "insecure X-Tenant-ID/X-User-ID authentication is development-only"
            )
        if self.environment != "development" and self.development_login_enabled:
            raise RuntimeError("development browser login is development-only")
        if self.environment != "development" and "change-me-before-use" in {
            self.bootstrap_token,
            self.job_claim_secret,
            self.development_session_secret,
        }:
            raise RuntimeError(
                "bootstrap, session and job claim secrets must be changed"
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_security()
    return settings
