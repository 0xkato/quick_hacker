"""Configuration settings for quick_hack backend."""

from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "quick_hack"
    debug: bool = True

    # Paths
    repos_dir: Path = Path("./repos")
    db_path: Path = Path("./data/quick_hack.db")

    # API Keys (optional - can be provided per-request)
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"

    # Agent settings
    max_concurrent_agents: int = 10
    agent_timeout_seconds: int = 300
    max_context_tokens: int = 128000

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
