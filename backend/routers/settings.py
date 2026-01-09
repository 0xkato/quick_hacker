"""Settings API endpoints for dynamic configuration."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Any

from services.settings_service import (
    settings_service,
    AppSettings,
    ProviderSettings,
    AgentDefaults,
    PromptConfig,
    UIPreferences,
    ModelConfig,
)
from middleware.auth import require_auth

# All settings endpoints require authentication
router = APIRouter(
    prefix="/settings",
    tags=["settings"],
    dependencies=[Depends(require_auth)],  # Protect all settings endpoints
)


# Request/Response Models
class UpdateProviderRequest(BaseModel):
    enabled: Optional[bool] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    default_model: Optional[str] = None
    custom_models: Optional[list[str]] = None  # User can add any model names
    rate_limit: Optional[int] = None


class UpdateAgentDefaultsRequest(BaseModel):
    default_provider: Optional[str] = None
    default_model: Optional[str] = None
    strict_mode_default: Optional[bool] = None
    max_concurrent_agents: Optional[int] = None
    auto_verify_findings: Optional[bool] = None
    confidence_threshold: Optional[float] = None


class CreatePromptRequest(BaseModel):
    id: str
    name: str
    description: str = ""
    prompt_text: str
    variables: list[str] = []
    category: str = "custom"


class UpdateUIPrefsRequest(BaseModel):
    theme: Optional[str] = None
    editor_font_size: Optional[int] = None
    show_line_numbers: Optional[bool] = None
    auto_expand_findings: Optional[bool] = None
    chat_position: Optional[str] = None
    chat_width: Optional[int] = None
    findings_panel_height: Optional[int] = None


# Endpoints
@router.get("")
async def get_all_settings():
    """Get all settings (API keys masked)."""
    return await settings_service.export_settings()


@router.get("/providers")
async def get_providers():
    """Get provider settings (API keys masked)."""
    settings = await settings_service.export_settings()
    return settings["providers"]


@router.put("/providers/{provider}")
async def update_provider(provider: str, request: UpdateProviderRequest):
    """Update settings for a specific provider."""
    settings = await settings_service.get_settings()

    if provider not in settings.providers:
        raise HTTPException(404, f"Provider not found: {provider}")

    current = settings.providers[provider]

    # Update only provided fields
    if request.enabled is not None:
        current.enabled = request.enabled
    if request.api_key is not None:
        current.api_key = request.api_key
    if request.base_url is not None:
        current.base_url = request.base_url
    if request.default_model is not None:
        current.default_model = request.default_model
    if request.custom_models is not None:
        current.custom_models = request.custom_models
    if request.rate_limit is not None:
        current.rate_limit = request.rate_limit

    success = await settings_service.update_provider(provider, current)
    if not success:
        raise HTTPException(500, "Failed to save provider settings")

    return {"status": "updated", "provider": provider}


@router.post("/providers/{provider}/test")
async def test_provider(provider: str):
    """Test provider connection with current settings."""
    settings = await settings_service.get_settings()

    if provider not in settings.providers:
        raise HTTPException(404, f"Provider not found: {provider}")

    provider_settings = settings.providers[provider]

    if not provider_settings.api_key and provider != "ollama":
        return {"status": "error", "message": "No API key configured"}

    # Import and test provider
    try:
        from models.schemas import ProviderConfig, ProviderType
        from providers import Message

        if provider == "openai":
            from providers.openai_provider import OpenAIProvider
            config = ProviderConfig(
                provider=ProviderType.OPENAI,
                model=provider_settings.default_model or "gpt-4o",
                api_key=provider_settings.api_key,
                max_tokens=16,
            )
            p = OpenAIProvider(config)
            await p.generate([Message(role="user", content="Say 'OK'")])
            return {"status": "success", "message": "Connected to OpenAI"}

        elif provider == "anthropic":
            from providers.anthropic_provider import AnthropicProvider
            config = ProviderConfig(
                provider=ProviderType.ANTHROPIC,
                model=provider_settings.default_model or "claude-sonnet-4-20250514",
                api_key=provider_settings.api_key,
                max_tokens=10,
            )
            p = AnthropicProvider(config)
            await p.generate([Message(role="user", content="Say 'OK'")])
            return {"status": "success", "message": "Connected to Anthropic"}

        elif provider == "ollama":
            from providers.ollama_provider import OllamaProvider
            config = ProviderConfig(
                provider=ProviderType.OLLAMA,
                model=provider_settings.default_model or "llama3.1",
                base_url=provider_settings.base_url,
            )
            p = OllamaProvider(config)
            models = await p.list_models()
            return {"status": "success", "message": f"Connected to Ollama ({len(models)} models)"}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/agent-defaults")
async def get_agent_defaults():
    """Get agent default settings."""
    settings = await settings_service.get_settings()
    return settings.agent_defaults


@router.put("/agent-defaults")
async def update_agent_defaults(request: UpdateAgentDefaultsRequest):
    """Update agent default settings."""
    settings = await settings_service.get_settings()
    current = settings.agent_defaults

    if request.default_provider is not None:
        current.default_provider = request.default_provider
    if request.default_model is not None:
        current.default_model = request.default_model
    if request.strict_mode_default is not None:
        current.strict_mode_default = request.strict_mode_default
    if request.max_concurrent_agents is not None:
        current.max_concurrent_agents = request.max_concurrent_agents
    if request.auto_verify_findings is not None:
        current.auto_verify_findings = request.auto_verify_findings
    if request.confidence_threshold is not None:
        current.confidence_threshold = request.confidence_threshold

    success = await settings_service.update_agent_defaults(current)
    if not success:
        raise HTTPException(500, "Failed to save agent defaults")

    return {"status": "updated"}


@router.get("/models")
async def get_model_configs():
    """Get all model configurations."""
    settings = await settings_service.get_settings()
    return settings.model_configs


@router.get("/prompts")
async def get_custom_prompts():
    """Get all custom prompts."""
    settings = await settings_service.get_settings()
    return settings.custom_prompts


@router.post("/prompts")
async def create_prompt(request: CreatePromptRequest):
    """Create a new custom prompt."""
    prompt = PromptConfig(**request.model_dump())
    success = await settings_service.add_custom_prompt(prompt)
    if not success:
        raise HTTPException(500, "Failed to save prompt")
    return {"status": "created", "id": prompt.id}


@router.put("/prompts/{prompt_id}")
async def update_prompt(prompt_id: str, request: CreatePromptRequest):
    """Update an existing custom prompt."""
    settings = await settings_service.get_settings()
    if prompt_id not in settings.custom_prompts:
        raise HTTPException(404, f"Prompt not found: {prompt_id}")

    prompt = PromptConfig(**request.model_dump())
    prompt.id = prompt_id
    success = await settings_service.add_custom_prompt(prompt)
    if not success:
        raise HTTPException(500, "Failed to update prompt")
    return {"status": "updated", "id": prompt_id}


@router.delete("/prompts/{prompt_id}")
async def delete_prompt(prompt_id: str):
    """Delete a custom prompt."""
    success = await settings_service.delete_custom_prompt(prompt_id)
    if not success:
        raise HTTPException(404, f"Prompt not found: {prompt_id}")
    return {"status": "deleted"}


@router.get("/ui")
async def get_ui_preferences():
    """Get UI preferences."""
    settings = await settings_service.get_settings()
    return settings.ui_preferences


@router.put("/ui")
async def update_ui_preferences(request: UpdateUIPrefsRequest):
    """Update UI preferences."""
    settings = await settings_service.get_settings()
    current = settings.ui_preferences

    if request.theme is not None:
        current.theme = request.theme
    if request.editor_font_size is not None:
        current.editor_font_size = request.editor_font_size
    if request.show_line_numbers is not None:
        current.show_line_numbers = request.show_line_numbers
    if request.auto_expand_findings is not None:
        current.auto_expand_findings = request.auto_expand_findings
    if request.chat_position is not None:
        current.chat_position = request.chat_position
    if request.chat_width is not None:
        current.chat_width = request.chat_width
    if request.findings_panel_height is not None:
        current.findings_panel_height = request.findings_panel_height

    success = await settings_service.update_ui_preferences(current)
    if not success:
        raise HTTPException(500, "Failed to save UI preferences")

    return {"status": "updated"}


@router.post("/export")
async def export_settings():
    """Export all settings as JSON."""
    return await settings_service.export_settings()


@router.post("/import")
async def import_settings(data: dict):
    """Import settings from JSON."""
    success = await settings_service.import_settings(data)
    if not success:
        raise HTTPException(400, "Failed to import settings")
    return {"status": "imported"}
