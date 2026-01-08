"""Model routing based on task type for cost optimization."""

from enum import Enum
from typing import Optional
from dataclasses import dataclass

from models.schemas import ProviderConfig, ProviderType
from providers import get_provider
from providers.base_provider import BaseProvider


class TaskType(Enum):
    """Types of tasks for model routing."""
    INITIAL_TRIAGE = "initial_triage"
    PROMPT_ENRICHMENT = "prompt_enrichment"
    PROMPT_REFINEMENT = "prompt_refinement"
    DEEP_ANALYSIS = "deep_analysis"
    VERIFICATION = "verification"
    POC_GENERATION = "poc_generation"
    PATCH_GENERATION = "patch_generation"


@dataclass
class ModelCost:
    """Cost tracking for model usage."""
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0


# Cost per 1M tokens (approximate)
MODEL_COSTS = {
    # Anthropic
    "claude-opus-4-5-20251101": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-3-5-sonnet-20241022": {"input": 3.0, "output": 15.0},
    "claude-3-5-haiku-20241022": {"input": 0.25, "output": 1.25},
    "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},
    # OpenAI
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    "gpt-4-turbo": {"input": 10.0, "output": 30.0},
    "o1-preview": {"input": 15.0, "output": 60.0},
    "o1-mini": {"input": 3.0, "output": 12.0},
    # Ollama (free, local)
    "llama3.3": {"input": 0.0, "output": 0.0},
    "codellama": {"input": 0.0, "output": 0.0},
    "deepseek-coder": {"input": 0.0, "output": 0.0},
}


class ModelRouter:
    """Routes tasks to appropriate models based on task type and cost."""

    # Default routing table: task_type -> (provider, model)
    ROUTING_TABLE = {
        # Fast, cheap tasks
        TaskType.INITIAL_TRIAGE: (ProviderType.OPENAI, "gpt-4o-mini"),
        TaskType.PROMPT_ENRICHMENT: (ProviderType.OPENAI, "gpt-4o-mini"),
        TaskType.PROMPT_REFINEMENT: (ProviderType.OPENAI, "gpt-4o-mini"),

        # Quality-critical tasks (use expensive models)
        TaskType.DEEP_ANALYSIS: (ProviderType.ANTHROPIC, "claude-opus-4-5-20251101"),
        TaskType.POC_GENERATION: (ProviderType.ANTHROPIC, "claude-opus-4-5-20251101"),

        # Balanced tasks
        TaskType.VERIFICATION: (ProviderType.OPENAI, "gpt-4o"),
        TaskType.PATCH_GENERATION: (ProviderType.OPENAI, "gpt-4o"),
    }

    # Fallback chain for each provider
    FALLBACK_CHAIN = {
        ProviderType.ANTHROPIC: [
            "claude-opus-4-5-20251101",
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
        ],
        ProviderType.OPENAI: [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
        ],
        ProviderType.OLLAMA: [
            "llama3.3",
            "codellama",
            "deepseek-coder",
        ],
    }

    def __init__(self, user_overrides: Optional[dict[TaskType, ProviderConfig]] = None):
        """Initialize router with optional user overrides."""
        self.user_overrides = user_overrides or {}
        self.cost_tracker: dict[str, ModelCost] = {}
        self.total_cost = ModelCost()

    def get_provider_config(
        self,
        task_type: TaskType,
        prefer_local: bool = False,
    ) -> ProviderConfig:
        """Get recommended provider config for a task type."""

        # Check user overrides first
        if task_type in self.user_overrides:
            return self.user_overrides[task_type]

        # Use local Ollama if preferred
        if prefer_local:
            return ProviderConfig(
                provider=ProviderType.OLLAMA,
                model="llama3.3",
                temperature=0.0,
                max_tokens=4096,
            )

        # Use routing table
        provider_type, model = self.ROUTING_TABLE.get(
            task_type,
            (ProviderType.OPENAI, "gpt-4o-mini")  # Default fallback
        )

        return ProviderConfig(
            provider=provider_type,
            model=model,
            temperature=0.0,
            max_tokens=4096,
        )

    def get_provider(
        self,
        task_type: TaskType,
        prefer_local: bool = False,
    ) -> BaseProvider:
        """Get provider instance for a task type."""
        config = self.get_provider_config(task_type, prefer_local)
        return get_provider(config)

    def track_usage(
        self,
        task_type: TaskType,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """Track token usage and estimate cost."""
        costs = MODEL_COSTS.get(model, {"input": 0.0, "output": 0.0})

        cost = (
            (input_tokens / 1_000_000) * costs["input"] +
            (output_tokens / 1_000_000) * costs["output"]
        )

        # Track per task type
        task_key = task_type.value
        if task_key not in self.cost_tracker:
            self.cost_tracker[task_key] = ModelCost()

        self.cost_tracker[task_key].input_tokens += input_tokens
        self.cost_tracker[task_key].output_tokens += output_tokens
        self.cost_tracker[task_key].estimated_cost_usd += cost

        # Track total
        self.total_cost.input_tokens += input_tokens
        self.total_cost.output_tokens += output_tokens
        self.total_cost.estimated_cost_usd += cost

        return cost

    def get_cost_summary(self) -> dict:
        """Get cost summary for all tracked usage."""
        return {
            "total": {
                "input_tokens": self.total_cost.input_tokens,
                "output_tokens": self.total_cost.output_tokens,
                "estimated_cost_usd": round(self.total_cost.estimated_cost_usd, 4),
            },
            "by_task": {
                task: {
                    "input_tokens": cost.input_tokens,
                    "output_tokens": cost.output_tokens,
                    "estimated_cost_usd": round(cost.estimated_cost_usd, 4),
                }
                for task, cost in self.cost_tracker.items()
            },
        }

    def get_cheap_model(self, provider: ProviderType = ProviderType.OPENAI) -> ProviderConfig:
        """Get the cheapest model for a provider."""
        cheap_models = {
            ProviderType.OPENAI: "gpt-4o-mini",
            ProviderType.ANTHROPIC: "claude-3-5-haiku-20241022",
            ProviderType.OLLAMA: "llama3.3",
        }
        return ProviderConfig(
            provider=provider,
            model=cheap_models.get(provider, "gpt-4o-mini"),
            temperature=0.0,
            max_tokens=4096,
        )

    def get_expensive_model(self, provider: ProviderType = ProviderType.ANTHROPIC) -> ProviderConfig:
        """Get the most capable model for a provider."""
        expensive_models = {
            ProviderType.ANTHROPIC: "claude-opus-4-5-20251101",
            ProviderType.OPENAI: "gpt-4o",
            ProviderType.OLLAMA: "llama3.3",
        }
        return ProviderConfig(
            provider=provider,
            model=expensive_models.get(provider, "claude-opus-4-5-20251101"),
            temperature=0.0,
            max_tokens=4096,
        )
