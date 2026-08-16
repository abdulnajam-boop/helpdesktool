from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="HELPDESK_", extra="ignore"
    )

    database_url: str = "postgresql+psycopg://helpdesk:helpdesk@localhost:5432/helpdesk"
    bootstrap_token: str = "change-me-before-use"
    environment: str = "development"

    def validate_security(self) -> None:
        if (
            self.environment != "development"
            and self.bootstrap_token == "change-me-before-use"
        ):
            raise RuntimeError(
                "HELPDESK_BOOTSTRAP_TOKEN must be changed outside development"
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_security()
    return settings
