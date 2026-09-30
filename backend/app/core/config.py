from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    mysql_url: str = f"sqlite:///{(BASE_DIR / 'data' / 'phishkg.db').as_posix()}"
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    jwt_secret: str = "dev-secret-change-me"
    jwt_expire_minutes: int = 120
    mail_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    data_dir: str = ""

    model_config = SettingsConfigDict(
        env_file=(str(BASE_DIR / ".env"), str(BASE_DIR.parent / ".env")),
        extra="ignore",
    )

    @property
    def data_path(self) -> Path:
        raw = Path(self.data_dir) if self.data_dir else BASE_DIR / "data"
        if not raw.is_absolute():
            raw = BASE_DIR / raw
        raw.mkdir(parents=True, exist_ok=True)
        return raw


@lru_cache
def get_settings() -> Settings:
    return Settings()
