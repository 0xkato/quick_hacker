"""Multi-stage prompt pipeline for optimized security analysis."""

from enum import Enum
from typing import Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from models.schemas import ProviderConfig, ProviderType
from providers import get_provider
from providers.base_provider import Message
from .model_router import ModelRouter, TaskType


class PipelineStage(Enum):
    """Stages in the prompt pipeline."""
    ENRICHMENT = "enrichment"      # Add context, expand scope
    REFINEMENT = "refinement"      # Self-critique, improve prompt
    EXECUTION = "execution"        # Main analysis with expensive model
    VERIFICATION = "verification"  # Validate findings, rate confidence


@dataclass
class StageResult:
    """Result from a pipeline stage."""
    stage: PipelineStage
    input_prompt: str
    output: str
    model_used: str
    tokens_in: int
    tokens_out: int
    duration_ms: int
    success: bool
    error: Optional[str] = None


@dataclass
class PipelineConfig:
    """Configuration for the prompt pipeline."""
    # Which stages to run
    enable_enrichment: bool = True
    enable_refinement: bool = True
    enable_verification: bool = True

    # Model preferences
    cheap_provider: ProviderType = ProviderType.OPENAI
    cheap_model: str = "gpt-4o-mini"
    expensive_provider: ProviderType = ProviderType.ANTHROPIC
    expensive_model: str = "claude-opus-4-5-20251101"

    # Behavior
    max_enrichment_tokens: int = 2000
    max_refinement_tokens: int = 2000
    max_execution_tokens: int = 8000
    max_verification_tokens: int = 2000

    # Local model preference
    prefer_local: bool = False


@dataclass
class PipelineResult:
    """Complete result from running the pipeline."""
    original_prompt: str
    enriched_prompt: Optional[str] = None
    refined_prompt: Optional[str] = None
    execution_output: str = ""
    verified_output: Optional[str] = None
    stages: list[StageResult] = field(default_factory=list)
    total_tokens_in: int = 0
    total_tokens_out: int = 0
    total_cost_usd: float = 0.0
    total_duration_ms: int = 0


class PromptPipeline:
    """
    Multi-stage prompt pipeline that uses cheap models for preparation
    and expensive models for the actual analysis.

    Flow:
    1. ENRICHMENT: Cheap model adds context, expands scope
    2. REFINEMENT: Cheap model critiques and improves the prompt
    3. EXECUTION: Expensive model performs deep analysis
    4. VERIFICATION: Cheap model validates findings
    """

    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        on_stage_start: Optional[Callable[[PipelineStage], None]] = None,
        on_stage_complete: Optional[Callable[[StageResult], None]] = None,
    ):
        self.config = config or PipelineConfig()
        self.router = ModelRouter()
        self.on_stage_start = on_stage_start
        self.on_stage_complete = on_stage_complete

        # Import stage handlers (lazy to avoid circular imports)
        from .enricher import PromptEnricher
        from .refiner import PromptRefiner
        from .verifier import PromptVerifier

        self.enricher = PromptEnricher()
        self.refiner = PromptRefiner()
        self.verifier = PromptVerifier()

    async def execute(
        self,
        base_prompt: str,
        code_context: str,
        system_prompt: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> PipelineResult:
        """
        Execute the full pipeline on the given prompt.

        Args:
            base_prompt: The user's original analysis request
            code_context: The code to analyze
            system_prompt: System prompt for the execution stage
            file_path: Optional file path for context
            language: Optional language hint
        """
        result = PipelineResult(original_prompt=base_prompt)
        current_prompt = base_prompt

        # Stage 1: Enrichment
        if self.config.enable_enrichment:
            stage_result = await self._run_enrichment(
                current_prompt, code_context, file_path, language
            )
            result.stages.append(stage_result)
            if stage_result.success:
                result.enriched_prompt = stage_result.output
                current_prompt = stage_result.output

        # Stage 2: Refinement
        if self.config.enable_refinement:
            stage_result = await self._run_refinement(
                current_prompt, code_context
            )
            result.stages.append(stage_result)
            if stage_result.success:
                result.refined_prompt = stage_result.output
                current_prompt = stage_result.output

        # Stage 3: Execution (main analysis)
        stage_result = await self._run_execution(
            current_prompt, code_context, system_prompt
        )
        result.stages.append(stage_result)
        result.execution_output = stage_result.output

        # Stage 4: Verification
        if self.config.enable_verification:
            stage_result = await self._run_verification(
                result.execution_output, code_context
            )
            result.stages.append(stage_result)
            if stage_result.success:
                result.verified_output = stage_result.output

        # Aggregate metrics
        for stage in result.stages:
            result.total_tokens_in += stage.tokens_in
            result.total_tokens_out += stage.tokens_out
            result.total_duration_ms += stage.duration_ms

        result.total_cost_usd = self.router.get_cost_summary()["total"]["estimated_cost_usd"]

        return result

    async def _run_enrichment(
        self,
        prompt: str,
        code_context: str,
        file_path: Optional[str],
        language: Optional[str],
    ) -> StageResult:
        """Run the enrichment stage."""
        if self.on_stage_start:
            self.on_stage_start(PipelineStage.ENRICHMENT)

        start = datetime.now()
        config = self._get_cheap_config()

        try:
            output, tokens_in, tokens_out = await self.enricher.enrich(
                prompt=prompt,
                code_context=code_context,
                file_path=file_path,
                language=language,
                provider_config=config,
            )

            self.router.track_usage(
                TaskType.PROMPT_ENRICHMENT,
                config.model,
                tokens_in,
                tokens_out,
            )

            result = StageResult(
                stage=PipelineStage.ENRICHMENT,
                input_prompt=prompt,
                output=output,
                model_used=config.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=True,
            )
        except Exception as e:
            result = StageResult(
                stage=PipelineStage.ENRICHMENT,
                input_prompt=prompt,
                output=prompt,  # Fallback to original
                model_used=config.model,
                tokens_in=0,
                tokens_out=0,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=False,
                error=str(e),
            )

        if self.on_stage_complete:
            self.on_stage_complete(result)

        return result

    async def _run_refinement(
        self,
        prompt: str,
        code_context: str,
    ) -> StageResult:
        """Run the refinement stage."""
        if self.on_stage_start:
            self.on_stage_start(PipelineStage.REFINEMENT)

        start = datetime.now()
        config = self._get_cheap_config()

        try:
            output, tokens_in, tokens_out = await self.refiner.refine(
                prompt=prompt,
                code_context=code_context,
                provider_config=config,
            )

            self.router.track_usage(
                TaskType.PROMPT_REFINEMENT,
                config.model,
                tokens_in,
                tokens_out,
            )

            result = StageResult(
                stage=PipelineStage.REFINEMENT,
                input_prompt=prompt,
                output=output,
                model_used=config.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=True,
            )
        except Exception as e:
            result = StageResult(
                stage=PipelineStage.REFINEMENT,
                input_prompt=prompt,
                output=prompt,
                model_used=config.model,
                tokens_in=0,
                tokens_out=0,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=False,
                error=str(e),
            )

        if self.on_stage_complete:
            self.on_stage_complete(result)

        return result

    async def _run_execution(
        self,
        prompt: str,
        code_context: str,
        system_prompt: str,
    ) -> StageResult:
        """Run the main execution stage with expensive model."""
        if self.on_stage_start:
            self.on_stage_start(PipelineStage.EXECUTION)

        start = datetime.now()
        config = self._get_expensive_config()

        try:
            provider = get_provider(config)

            # Combine prompt with code context
            full_prompt = f"{prompt}\n\n---\n\nCode to analyze:\n```\n{code_context}\n```"

            messages = [Message(role="user", content=full_prompt)]
            output = await provider.generate(messages, system_prompt)

            # Estimate tokens (actual counting would be model-specific)
            tokens_in = len(full_prompt) // 4 + len(system_prompt) // 4
            tokens_out = len(output) // 4

            self.router.track_usage(
                TaskType.DEEP_ANALYSIS,
                config.model,
                tokens_in,
                tokens_out,
            )

            result = StageResult(
                stage=PipelineStage.EXECUTION,
                input_prompt=prompt,
                output=output,
                model_used=config.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=True,
            )
        except Exception as e:
            result = StageResult(
                stage=PipelineStage.EXECUTION,
                input_prompt=prompt,
                output="",
                model_used=config.model,
                tokens_in=0,
                tokens_out=0,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=False,
                error=str(e),
            )

        if self.on_stage_complete:
            self.on_stage_complete(result)

        return result

    async def _run_verification(
        self,
        analysis_output: str,
        code_context: str,
    ) -> StageResult:
        """Run the verification stage."""
        if self.on_stage_start:
            self.on_stage_start(PipelineStage.VERIFICATION)

        start = datetime.now()
        config = self._get_cheap_config()

        try:
            output, tokens_in, tokens_out = await self.verifier.verify(
                analysis_output=analysis_output,
                code_context=code_context,
                provider_config=config,
            )

            self.router.track_usage(
                TaskType.VERIFICATION,
                config.model,
                tokens_in,
                tokens_out,
            )

            result = StageResult(
                stage=PipelineStage.VERIFICATION,
                input_prompt=analysis_output[:500] + "...",
                output=output,
                model_used=config.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=True,
            )
        except Exception as e:
            result = StageResult(
                stage=PipelineStage.VERIFICATION,
                input_prompt=analysis_output[:500] + "...",
                output=analysis_output,
                model_used=config.model,
                tokens_in=0,
                tokens_out=0,
                duration_ms=int((datetime.now() - start).total_seconds() * 1000),
                success=False,
                error=str(e),
            )

        if self.on_stage_complete:
            self.on_stage_complete(result)

        return result

    def _get_cheap_config(self) -> ProviderConfig:
        """Get config for cheap model."""
        if self.config.prefer_local:
            return ProviderConfig(
                provider=ProviderType.OLLAMA,
                model="llama3.3",
                temperature=0.0,
                max_tokens=self.config.max_enrichment_tokens,
            )

        return ProviderConfig(
            provider=self.config.cheap_provider,
            model=self.config.cheap_model,
            temperature=0.0,
            max_tokens=self.config.max_enrichment_tokens,
        )

    def _get_expensive_config(self) -> ProviderConfig:
        """Get config for expensive model."""
        if self.config.prefer_local:
            return ProviderConfig(
                provider=ProviderType.OLLAMA,
                model="llama3.3",
                temperature=0.0,
                max_tokens=self.config.max_execution_tokens,
            )

        return ProviderConfig(
            provider=self.config.expensive_provider,
            model=self.config.expensive_model,
            temperature=0.0,
            max_tokens=self.config.max_execution_tokens,
        )
