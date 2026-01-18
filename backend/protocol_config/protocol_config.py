"""Protocol layer configuration."""

import os
from typing import Optional


class ProtocolConfig:
    """Configuration for protocol evaluation and quests."""

    # Quest LLM settings
    QUEST_LLM_MODEL: str = os.getenv(
        "QUEST_LLM_MODEL",
        "claude-3-5-sonnet-20241022"
    )
    QUEST_TIMEOUT_SECONDS: int = int(os.getenv("QUEST_TIMEOUT_SECONDS", "120"))
    QUEST_MAX_RETRIES: int = int(os.getenv("QUEST_MAX_RETRIES", "1"))

    # Production filter LLM settings
    PRODUCTION_FILTER_MODEL: str = os.getenv(
        "PRODUCTION_FILTER_MODEL",
        "claude-3-5-haiku-20241022"  # Fast, cheap model for filtering
    )
    PRODUCTION_FILTER_MAX_TOKENS: int = int(os.getenv("PRODUCTION_FILTER_MAX_TOKENS", "200"))
    PRODUCTION_FILTER_TEMPERATURE: float = float(os.getenv("PRODUCTION_FILTER_TEMPERATURE", "0"))

    # Quest behavior
    ENABLE_QUESTS_BY_DEFAULT: bool = os.getenv(
        "ENABLE_QUESTS_BY_DEFAULT",
        "true"
    ).lower() == "true"

    # Protocol defaults
    DEFAULT_PROTOCOL_ID: str = os.getenv("DEFAULT_PROTOCOL_ID", "internal")

    # Feature flags
    ENABLE_PROTOCOL_EVALUATION: bool = os.getenv(
        "ENABLE_PROTOCOL_EVALUATION",
        "true"
    ).lower() == "true"

    # LLM API keys
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")

    @classmethod
    def validate(cls):
        """Validate configuration."""
        if cls.ENABLE_QUESTS_BY_DEFAULT and not cls.ANTHROPIC_API_KEY:
            print("⚠️  Warning: Quests enabled but no ANTHROPIC_API_KEY set")


# Validate on import
ProtocolConfig.validate()
