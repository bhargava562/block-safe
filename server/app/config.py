"""
BlockSafe Configuration Module
Secure settings management with environment variable loading
"""

from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Uses SecretStr to prevent accidental logging of sensitive values.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Required secrets
    GEMINI_API_KEY: SecretStr
    API_AUTH_KEY: SecretStr

    # Configurable limits
    MAX_AUDIO_MB: int = 10

    # Gemini model configuration
    GEMINI_MODEL: str = "gemini-1.5-flash"

    # Honeypot configuration
    HONEYPOT_MAX_TURNS: int = 5
    HONEYPOT_CONFIDENCE_THRESHOLD: float = 0.85
    HONEYPOT_NO_PROGRESS_TURNS: int = 2

    # Whisper configuration
    WHISPER_MODEL_SIZE: str = "base"
    WHISPER_DEVICE: str = "cpu"
    WHISPER_COMPUTE_TYPE: str = "int8"

    @field_validator("MAX_AUDIO_MB")
    @classmethod
    def validate_max_audio(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("MAX_AUDIO_MB must be positive")
        if v > 100:
            raise ValueError("MAX_AUDIO_MB cannot exceed 100MB")
        return v

    @field_validator("HONEYPOT_CONFIDENCE_THRESHOLD")
    @classmethod
    def validate_confidence_threshold(cls, v: float) -> float:
        if not 0 <= v <= 1:
            raise ValueError("HONEYPOT_CONFIDENCE_THRESHOLD must be between 0 and 1")
        return v


@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached Settings instance.
    Uses lru_cache to ensure settings are only loaded once.
    """
    return Settings()
