"""
BlockSafe Configuration Module
Secure, memory-safe settings management with environment variable loading.

Design Goals:
  - Zero memory leaks: bounded caches, no unbounded collections
  - Crash-proof: all external provider keys are Optional with graceful fallback
  - Performance: single-instance singleton via lru_cache, lazy provider init
"""

from functools import lru_cache
from typing import Optional, List

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Uses SecretStr to prevent accidental logging of sensitive values.

    All AI provider keys are Optional — the app degrades gracefully
    when a provider is not configured instead of crashing on startup.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # -----------------------------------------------------------------
    # 1. APPLICATION
    # -----------------------------------------------------------------
    APP_ENV: str = "production"             # development | production | testing
    LOG_LEVEL: str = "INFO"                 # DEBUG | INFO | WARNING | ERROR
    CORS_ORIGINS: str = "*"                 # comma-separated origins

    # -----------------------------------------------------------------
    # 2. REQUIRED SECRETS
    # -----------------------------------------------------------------
    GEMINI_API_KEY: SecretStr
    API_AUTH_KEY: SecretStr

    # -----------------------------------------------------------------
    # 3. OPTIONAL AI PROVIDER KEYS (no crash if absent)
    # -----------------------------------------------------------------
    OPENAI_API_KEY: Optional[SecretStr] = None
    GROQ_API_KEY: Optional[SecretStr] = None

    # -----------------------------------------------------------------
    # 4. MODEL NAMES (read from env, sensible defaults)
    # -----------------------------------------------------------------
    GEMINI_MODEL: str = "gemini-2.5-flash"
    OPENAI_MODEL: str = "gpt-4o-mini"
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    # -----------------------------------------------------------------
    # 5. AUDIO / WHISPER
    # -----------------------------------------------------------------
    MAX_AUDIO_MB: int = 10
    WHISPER_MODEL_SIZE: str = "base"
    WHISPER_DEVICE: str = "cpu"
    WHISPER_COMPUTE_TYPE: str = "int8"

    # -----------------------------------------------------------------
    # 6. HONEYPOT
    # -----------------------------------------------------------------
    HONEYPOT_MAX_TURNS: int = 5
    HONEYPOT_CONFIDENCE_THRESHOLD: float = 0.85
    HONEYPOT_NO_PROGRESS_TURNS: int = 2

    # -----------------------------------------------------------------
    # 7. PERFORMANCE TUNING
    # -----------------------------------------------------------------
    CLASSIFICATION_CACHE_MAX: int = 256     # bounded LRU cache size
    CLASSIFICATION_CACHE_TTL: int = 300     # cache TTL in seconds
    REQUEST_TIMEOUT_SECONDS: int = 30       # max time for AI provider calls
    MAX_CONCURRENT_REQUESTS: int = 100      # concurrency semaphore limit
    THREAD_POOL_WORKERS: int = 4            # thread pool for CPU-bound work (audio)
    RATE_LIMIT_MAX_CLIENTS: int = 10000     # max tracked clients (memory cap)

    # -----------------------------------------------------------------
    # 8. DATASET MERGING
    # -----------------------------------------------------------------
    MERGE_SIMILARITY_THRESHOLD: float = 0.6 # threshold for campaign merging (0-1)

    # -----------------------------------------------------------------
    # 9. MULTI-AGENT ORCHESTRATION
    # -----------------------------------------------------------------
    COGNITIVE_RISK_THRESHOLD: float = 0.7   # risk_score threshold → scam intervention
    AGENT_TIMEOUT_SECONDS: int = 15         # per-agent timeout for LangChain chains

    # -----------------------------------------------------------------
    # VALIDATORS
    # -----------------------------------------------------------------

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

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        allowed = {"development", "production", "testing"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()

    @field_validator("CLASSIFICATION_CACHE_MAX")
    @classmethod
    def validate_cache_max(cls, v: int) -> int:
        if v < 1:
            raise ValueError("CLASSIFICATION_CACHE_MAX must be >= 1")
        if v > 10000:
            raise ValueError("CLASSIFICATION_CACHE_MAX cannot exceed 10000 (memory safety)")
        return v

    @field_validator("THREAD_POOL_WORKERS")
    @classmethod
    def validate_thread_pool(cls, v: int) -> int:
        if v < 1:
            raise ValueError("THREAD_POOL_WORKERS must be >= 1")
        if v > 16:
            raise ValueError("THREAD_POOL_WORKERS cannot exceed 16 (resource safety)")
        return v

    # -----------------------------------------------------------------
    # HELPERS
    # -----------------------------------------------------------------

    @property
    def cors_origin_list(self) -> List[str]:
        """Parse comma-separated CORS_ORIGINS into a list."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def has_openai(self) -> bool:
        """Check if OpenAI provider is configured (key present and non-empty)."""
        return self.OPENAI_API_KEY is not None and bool(
            self.OPENAI_API_KEY.get_secret_value()
        )

    @property
    def has_groq(self) -> bool:
        """Check if Groq provider is configured (key present and non-empty)."""
        return self.GROQ_API_KEY is not None and bool(
            self.GROQ_API_KEY.get_secret_value()
        )


@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached Settings instance.
    Uses lru_cache to ensure settings are only loaded once (singleton).
    """
    return Settings()
