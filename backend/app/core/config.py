from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # ── Database ──
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/security_db"

    # ── Redis ──
    REDIS_URL: str = "redis://localhost:6379"

    # ── JWT ──
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_MIN_32_CHARS_LONG"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60

    # ── Ollama LLM ──
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:1.5b"
    OLLAMA_TIMEOUT: int = 180

    # ── Webhooks ──
    SLACK_WEBHOOK_URL: str = ""
    SIEM_WEBHOOK_URL: str = ""

    # ── ML ──
    ML_MODEL_PATH: str = "app/ml/models/isolation_forest.pkl"
    ML_SCALER_PATH: str = "app/ml/models/scaler.pkl"
    ML_CONTAMINATION: float = 0.05
    ML_N_ESTIMATORS: int = 200

    # ── Scoring Weights ──
    STATIC_WEIGHT: float = 0.60
    ML_WEIGHT: float = 0.40

    # ── Threat Thresholds ──
    THRESHOLD_LOW: float = 0.20
    THRESHOLD_MEDIUM: float = 0.40
    THRESHOLD_HIGH: float = 0.65
    THRESHOLD_CRITICAL: float = 0.85

    # ── App ──
    APP_NAME: str = "Anti-Tampering Security API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
