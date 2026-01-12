"""Configuration settings for quick_hack backend."""

from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "quick_hack"
    debug: bool = True

    # JWT Auth
    jwt_secret_key: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_USE_RANDOM_64_CHAR_STRING",
        description="Secret key for JWT encoding"
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60 * 24  # 24 hours
    jwt_refresh_token_expire_days: int = 30

    # Paths
    repos_dir: Path = Path("./repos")
    db_path: Path = Path("./data/quick_hack.db")

    # API Keys (optional - can be provided per-request)
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    anthropic_auth_token: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"

    # Agent settings
    max_concurrent_agents: int = 10
    agent_timeout_seconds: int = 300
    max_context_tokens: int = 128000

    # Triage system configuration
    triage_enabled: bool = Field(
        default=True,
        description="Enable vulnerability triage system"
    )
    triage_policy_version: str = Field(
        default="1.0.0",
        description="Triage policy version for tracking rule changes"
    )
    triage_batch_budget_ms: int = Field(
        default=15000,
        description="Maximum time for triage batch in milliseconds"
    )
    triage_per_finding_budget_ms: int = Field(
        default=300,
        description="Maximum time per finding in milliseconds"
    )
    triage_max_evidence_bytes: int = Field(
        default=10000,
        description="Maximum evidence size per finding in bytes"
    )
    triage_max_snippet_lines: int = Field(
        default=200,
        description="Maximum lines in code snippets"
    )
    triage_enable_redaction: bool = Field(
        default=True,
        description="Redact secrets in evidence snippets"
    )
    triage_show_filtered_by_default: bool = Field(
        default=False,
        description="Show non-reportable findings by default in UI"
    )
    triage_allow_manual_override: bool = Field(
        default=True,
        description="Allow manual disposition override (log/audit overrides)"
    )

    # Sandbox settings
    sandbox_enabled: bool = True
    sandbox_timeout_seconds: int = 30
    sandbox_memory_limit: str = "256m"
    sandbox_network_disabled: bool = True

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Auth bootstrap (development convenience)
    # By default, the token minting endpoints (/api/auth/*) are localhost-only.
    auth_bootstrap_allow_remote: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# Ensure directories exist
settings.repos_dir.mkdir(parents=True, exist_ok=True)
settings.db_path.parent.mkdir(parents=True, exist_ok=True)
