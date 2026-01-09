"""
Dynamic Settings Service - Persistent configuration storage.

Supports:
- API key management (encrypted at rest)
- Model configurations
- Custom prompts
- Agent defaults
- UI preferences
"""

import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field
import aiofiles
import asyncio


class ProviderSettings(BaseModel):
    """Settings for an AI provider."""
    enabled: bool = True
    api_key: str = ""  # Stored encrypted
    base_url: Optional[str] = None
    default_model: str = ""
    available_models: list[str] = []  # Suggested models (user can enter any)
    custom_models: list[str] = []  # User-added custom model names
    rate_limit: int = 60  # requests per minute
    timeout: int = 120  # seconds


class ModelConfig(BaseModel):
    """Configuration for a specific model."""
    provider: str
    model_id: str
    display_name: str
    tier: str = "standard"  # cheap, standard, premium
    max_tokens: int = 4096
    temperature: float = 0.0
    supports_streaming: bool = True
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0


class AgentDefaults(BaseModel):
    """Default settings for agents."""
    default_provider: str = "anthropic"
    default_model: str = "claude-sonnet-4-20250514"
    strict_mode_default: bool = True
    max_concurrent_agents: int = 5
    auto_verify_findings: bool = True
    confidence_threshold: float = 0.85


class PromptConfig(BaseModel):
    """Custom prompt configuration."""
    id: str
    name: str
    description: str = ""
    prompt_text: str
    variables: list[str] = []
    category: str = "custom"  # system, analysis, verification, custom
    is_default: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UIPreferences(BaseModel):
    """UI preferences."""
    theme: str = "dark"
    editor_font_size: int = 14
    show_line_numbers: bool = True
    auto_expand_findings: bool = True
    chat_position: str = "left"  # left, right, bottom
    chat_width: int = 400
    findings_panel_height: int = 300


class AppSettings(BaseModel):
    """Complete application settings."""
    providers: dict[str, ProviderSettings] = {
        "openai": ProviderSettings(
            default_model="gpt-4o",
            available_models=["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-5.2", "o1", "o1-mini"]
        ),
        "anthropic": ProviderSettings(
            default_model="claude-sonnet-4-20250514",
            available_models=["claude-opus-4-5-20251101", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"]
        ),
        "ollama": ProviderSettings(
            base_url="http://ollama:11434",
            default_model="llama3.1",
            available_models=["llama3.1", "codellama", "mistral", "mixtral", "deepseek-coder"]
        ),
    }
    model_configs: dict[str, ModelConfig] = {}
    agent_defaults: AgentDefaults = AgentDefaults()
    custom_prompts: dict[str, PromptConfig] = {}
    ui_preferences: UIPreferences = UIPreferences()
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class SettingsService:
    """
    Service for managing application settings with file persistence.

    Settings are stored in JSON format in the data directory.
    API keys are obfuscated (not true encryption, but better than plaintext).
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.settings_file = self.data_dir / "settings.json"
        self._settings: Optional[AppSettings] = None
        self._lock = asyncio.Lock()
        self._secret = os.environ.get("SETTINGS_SECRET", "quick_hack_default_key")

    async def initialize(self):
        """Initialize the settings service."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        await self.load()

    async def load(self) -> AppSettings:
        """Load settings from file."""
        async with self._lock:
            if self.settings_file.exists():
                try:
                    async with aiofiles.open(self.settings_file, 'r') as f:
                        data = json.loads(await f.read())
                        self._settings = AppSettings(**data)
                        # Decode API keys
                        for provider in self._settings.providers.values():
                            if provider.api_key:
                                provider.api_key = self._decode(provider.api_key)
                except Exception as e:
                    print(f"Error loading settings: {e}")
                    self._settings = self._create_defaults()
            else:
                self._settings = self._create_defaults()

            return self._settings

    async def save(self) -> bool:
        """Save settings to file."""
        async with self._lock:
            if not self._settings:
                return False

            try:
                # Create a copy for saving (encode API keys)
                save_data = self._settings.model_dump()
                for provider_name, provider_data in save_data["providers"].items():
                    if provider_data.get("api_key"):
                        provider_data["api_key"] = self._encode(provider_data["api_key"])

                save_data["updated_at"] = datetime.utcnow().isoformat()

                async with aiofiles.open(self.settings_file, 'w') as f:
                    await f.write(json.dumps(save_data, indent=2, default=str))

                return True
            except Exception as e:
                print(f"Error saving settings: {e}")
                return False

    def _create_defaults(self) -> AppSettings:
        """Create default settings, pulling API keys from environment."""
        settings = AppSettings()

        # Pull API keys from environment
        if os.environ.get("OPENAI_API_KEY"):
            settings.providers["openai"].api_key = os.environ["OPENAI_API_KEY"]
        if os.environ.get("ANTHROPIC_API_KEY"):
            settings.providers["anthropic"].api_key = os.environ["ANTHROPIC_API_KEY"]
        if os.environ.get("OLLAMA_BASE_URL"):
            settings.providers["ollama"].base_url = os.environ["OLLAMA_BASE_URL"]

        # Add default model configs
        settings.model_configs = {
            "claude-opus-4-5": ModelConfig(
                provider="anthropic",
                model_id="claude-opus-4-5-20251101",
                display_name="Claude Opus 4.5",
                tier="premium",
                max_tokens=8192,
                cost_per_1k_input=0.015,
                cost_per_1k_output=0.075,
            ),
            "claude-sonnet": ModelConfig(
                provider="anthropic",
                model_id="claude-sonnet-4-20250514",
                display_name="Claude Sonnet 4",
                tier="standard",
                max_tokens=8192,
                cost_per_1k_input=0.003,
                cost_per_1k_output=0.015,
            ),
            "claude-haiku": ModelConfig(
                provider="anthropic",
                model_id="claude-3-5-haiku-20241022",
                display_name="Claude 3.5 Haiku",
                tier="cheap",
                max_tokens=8192,
                cost_per_1k_input=0.001,
                cost_per_1k_output=0.005,
            ),
            "gpt-4o": ModelConfig(
                provider="openai",
                model_id="gpt-4o",
                display_name="GPT-4o",
                tier="standard",
                max_tokens=4096,
                cost_per_1k_input=0.005,
                cost_per_1k_output=0.015,
            ),
            "gpt-4o-mini": ModelConfig(
                provider="openai",
                model_id="gpt-4o-mini",
                display_name="GPT-4o Mini",
                tier="cheap",
                max_tokens=4096,
                cost_per_1k_input=0.00015,
                cost_per_1k_output=0.0006,
            ),
        }

        return settings

    def _encode(self, value: str) -> str:
        """Simple obfuscation for API keys (not cryptographic security)."""
        if not value:
            return ""
        # XOR with secret key
        key = hashlib.sha256(self._secret.encode()).digest()
        encoded = bytes([b ^ key[i % len(key)] for i, b in enumerate(value.encode())])
        return encoded.hex()

    def _decode(self, value: str) -> str:
        """Decode obfuscated value."""
        if not value:
            return ""
        try:
            key = hashlib.sha256(self._secret.encode()).digest()
            decoded = bytes([b ^ key[i % len(key)] for i, b in enumerate(bytes.fromhex(value))])
            return decoded.decode()
        except Exception:
            return value  # Return as-is if decoding fails (might be plaintext)

    @property
    def settings(self) -> AppSettings:
        """Get current settings (must call load() first)."""
        if not self._settings:
            raise RuntimeError("Settings not loaded. Call initialize() first.")
        return self._settings

    async def get_settings(self) -> AppSettings:
        """Get settings, loading if necessary."""
        if not self._settings:
            await self.load()
        return self._settings

    async def update_provider(self, provider: str, settings: ProviderSettings) -> bool:
        """Update provider settings."""
        if not self._settings:
            await self.load()

        self._settings.providers[provider] = settings
        return await self.save()

    async def update_api_key(self, provider: str, api_key: str) -> bool:
        """Update API key for a provider."""
        if not self._settings:
            await self.load()

        if provider in self._settings.providers:
            self._settings.providers[provider].api_key = api_key
            return await self.save()
        return False

    async def update_agent_defaults(self, defaults: AgentDefaults) -> bool:
        """Update agent default settings."""
        if not self._settings:
            await self.load()

        self._settings.agent_defaults = defaults
        return await self.save()

    async def add_custom_prompt(self, prompt: PromptConfig) -> bool:
        """Add or update a custom prompt."""
        if not self._settings:
            await self.load()

        prompt.updated_at = datetime.utcnow()
        self._settings.custom_prompts[prompt.id] = prompt
        return await self.save()

    async def delete_custom_prompt(self, prompt_id: str) -> bool:
        """Delete a custom prompt."""
        if not self._settings:
            await self.load()

        if prompt_id in self._settings.custom_prompts:
            del self._settings.custom_prompts[prompt_id]
            return await self.save()
        return False

    async def update_ui_preferences(self, prefs: UIPreferences) -> bool:
        """Update UI preferences."""
        if not self._settings:
            await self.load()

        self._settings.ui_preferences = prefs
        return await self.save()

    async def export_settings(self) -> dict:
        """Export settings as dict (API keys masked)."""
        if not self._settings:
            await self.load()

        data = self._settings.model_dump()
        # Mask API keys
        for provider in data["providers"].values():
            if provider.get("api_key"):
                key = provider["api_key"]
                provider["api_key"] = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "****"

        return data

    async def import_settings(self, data: dict) -> bool:
        """Import settings from dict."""
        try:
            # Preserve existing API keys if not provided
            for provider, provider_data in data.get("providers", {}).items():
                if "..." in provider_data.get("api_key", "") or provider_data.get("api_key") == "****":
                    # Keep existing key
                    if self._settings and provider in self._settings.providers:
                        provider_data["api_key"] = self._settings.providers[provider].api_key

            self._settings = AppSettings(**data)
            return await self.save()
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False


# Global instance
settings_service = SettingsService(os.environ.get("DATA_DIR", "data"))
