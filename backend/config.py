"""Configuration settings for quick_hack backend."""

import json
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default CORS origins (defined once to avoid duplication)
DEFAULT_CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
DEFAULT_CORS_ORIGINS_STR = ",".join(DEFAULT_CORS_ORIGINS)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

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

    # Tool output caching
    tool_cache_enabled: bool = Field(
        default=True,
        description="Enable tool output caching for performance"
    )
    tool_cache_max_size: int = Field(
        default=1000,
        gt=0,  # Must be positive
        description="Maximum number of cached tool outputs (LRU eviction)"
    )
    tool_cache_ttl_seconds: int = Field(
        default=3600,
        gt=0,  # Must be positive
        description="Time-to-live for cached entries in seconds (default 1 hour)"
    )

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

    # Tool timeout settings (used by LLM validator and other tools)
    grep_timeout_seconds: int = Field(
        default=10,
        description="Timeout for grep/ripgrep operations in seconds"
    )
    gdb_timeout_seconds: int = Field(
        default=30,
        description="Timeout for GDB debugging operations in seconds"
    )
    validation_timeout_seconds: int = Field(
        default=120,
        description="Timeout for LLM validation operations in seconds"
    )
    file_read_max_bytes: int = Field(
        default=100000,
        description="Maximum bytes to read from a single file (100KB default)"
    )

    # Flow tracing settings
    max_call_depth: int = Field(
        default=3,
        description="Maximum call chain depth for flow tracing"
    )

    # CORS
    cors_origins: str = Field(
        default=DEFAULT_CORS_ORIGINS_STR,
        description=(
            "Allowed CORS origins. Supports comma-separated values or a JSON array (e.g. "
            "['http://localhost:3000'])."
        ),
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Return parsed CORS origins as a list.

        Pydantic-settings expects JSON for list fields, which is brittle with dotenv files.
        This keeps config robust by accepting either comma-separated strings or JSON.
        """
        raw = (self.cors_origins or "").strip()
        if not raw:
            return DEFAULT_CORS_ORIGINS.copy()

        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except Exception:
                # Fall back to comma-separated parsing below
                pass

        return [part.strip() for part in raw.split(",") if part.strip()]

    # Campaign platform settings
    max_concurrent_campaigns: int = Field(
        default=5,
        description="Maximum number of campaigns running simultaneously",
    )
    max_concurrent_runner_jobs: int = Field(
        default=4,
        description="Maximum concurrent runner (fuzz) jobs across all campaigns",
    )
    max_concurrent_lm_jobs: int = Field(
        default=2,
        description="Maximum concurrent LM (language model) jobs",
    )
    artifact_store_backend: str = Field(
        default="filesystem",
        description="Artifact store backend: 'filesystem' or 'minio'",
    )
    build_cache_ttl_seconds: int = Field(
        default=3600,
        description="TTL for build cache entries in seconds",
    )
    default_repro_attempts: int = Field(
        default=5,
        description="Default number of reproduction attempts per artifact",
    )
    default_minimization_budget_seconds: int = Field(
        default=60,
        description="Default time budget for artifact minimization in seconds",
    )
    state_reset_timeout_seconds: int = Field(
        default=30,
        description="Timeout for resetting target state between runs",
    )
    max_corpus_bytes_per_lane: int = Field(
        default=100 * 1024 * 1024,
        description="Maximum corpus size per lane in bytes (default 100MB)",
    )
    internet_egress_policy: str = Field(
        default="blocked",
        description="Internet egress policy for runner containers: 'blocked' or 'allowed'",
    )
    internal_service_network: bool = Field(
        default=True,
        description="Whether runners can reach internal services (e.g. target under test)",
    )
    runner_cpu_limit: str = Field(
        default="2",
        description="CPU limit for runner containers (Docker CPU quota)",
    )
    runner_memory_limit: str = Field(
        default="2048",
        description="Memory limit for runner containers in MB",
    )
    runner_disk_limit: str = Field(
        default="4096",
        description="Disk limit for runner containers in MB",
    )

    # Auth bootstrap (development convenience)
    # By default, the token minting endpoints (/api/auth/*) are localhost-only.
    auth_bootstrap_allow_remote: bool = False


settings = Settings()

# Security check: fail if using default JWT secret in non-debug mode
_DEFAULT_JWT_SECRET = "CHANGE_ME_IN_PRODUCTION_USE_RANDOM_64_CHAR_STRING"
if not settings.debug and settings.jwt_secret_key == _DEFAULT_JWT_SECRET:
    raise RuntimeError(
        "SECURITY ERROR: Cannot use default JWT secret in production (debug=False). "
        "Set JWT_SECRET_KEY environment variable to a secure random string."
    )

# Ensure directories exist
settings.repos_dir.mkdir(parents=True, exist_ok=True)
settings.db_path.parent.mkdir(parents=True, exist_ok=True)
