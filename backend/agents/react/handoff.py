"""Scanner to analyzer handoff management.

This module manages the transition from scanner phase (fast exploration)
to analyzer phase (deep analysis) in dual-model mode.
"""

from datetime import datetime
from typing import Optional, Callable

from models.schemas import (
    ScannerHandoffState,
    EntryPoint,
    Sink,
    FileReadRecord,
    WSMessage,
    WSMessageType,
    ProviderConfig,
)
from agents.prompts.analyzer_prompt import format_analyzer_prompt
from prompting_loader import load_prompt
from services.observability_service import observability_service


class HandoffManager:
    """Manages handoff from scanner to analyzer phase."""

    def __init__(
        self,
        agent_id: str,
        repo_path: str,
        scanner_config: Optional[ProviderConfig],
        analyzer_config: Optional[ProviderConfig],
        broadcast_fn: Optional[Callable[[WSMessageType, dict], None]] = None,
        log_fn: Optional[Callable[[str, str], None]] = None,
    ):
        """
        Initialize handoff manager.

        Args:
            agent_id: Agent identifier
            repo_path: Repository path
            scanner_config: Scanner provider configuration
            analyzer_config: Analyzer provider configuration
            broadcast_fn: Function to broadcast websocket messages
            log_fn: Function to log messages
        """
        self.agent_id = agent_id
        self.repo_path = repo_path
        self.scanner_config = scanner_config
        self.analyzer_config = analyzer_config
        self._broadcast = broadcast_fn
        self._log = log_fn
        self._handoff_state: Optional[ScannerHandoffState] = None

    def init_handoff_state(self) -> ScannerHandoffState:
        """Initialize empty handoff state for scanner phase."""
        self._handoff_state = ScannerHandoffState(
            repo_path=self.repo_path,
            scanner_model=self.scanner_config.model if self.scanner_config else "",
        )
        return self._handoff_state

    def add_entry_point(
        self,
        name: str,
        file_path: str,
        line_number: int,
        code_snippet: str,
        method: Optional[str] = None,
        route: Optional[str] = None,
    ) -> None:
        """
        Add an entry point to handoff state.

        Args:
            name: Entry point name
            file_path: File containing entry point
            line_number: Line number
            code_snippet: Code snippet
            method: HTTP method (if applicable)
            route: Route pattern (if applicable)
        """
        if not self._handoff_state:
            return

        ep = EntryPoint(
            name=name,
            file_path=file_path,
            line_number=line_number,
            method=method,
            route=route,
            code_snippet=code_snippet,
        )
        self._handoff_state.entry_points.append(ep)

    def add_sink(
        self,
        sink_type: str,
        function_name: str,
        file_path: str,
        line_number: int,
        code_snippet: str,
        context: Optional[str] = None,
    ) -> None:
        """
        Add a dangerous sink to handoff state.

        Args:
            sink_type: Type of sink (e.g., "sql", "command_injection")
            function_name: Function name
            file_path: File containing sink
            line_number: Line number
            code_snippet: Code snippet
            context: Additional context
        """
        if not self._handoff_state:
            return

        sink = Sink(
            sink_type=sink_type,
            function_name=function_name,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            context=context,
        )
        self._handoff_state.dangerous_sinks.append(sink)

    def record_file_read(
        self, path: str, relevance_score: float = 0.0, summary: Optional[str] = None
    ) -> None:
        """
        Record a file read during scanner phase.

        Args:
            path: File path
            relevance_score: Relevance score (0.0-1.0)
            summary: Optional summary
        """
        if not self._handoff_state:
            return

        record = FileReadRecord(
            path=path,
            relevance_score=relevance_score,
            summary=summary or "",
        )
        self._handoff_state.files_read.append(record)

    def get_handoff_state(self) -> Optional[ScannerHandoffState]:
        """Get current handoff state."""
        return self._handoff_state

    def should_handoff(self, handoff_reason: str = "SCANNING_COMPLETE") -> bool:
        """
        Check if handoff should occur.

        Args:
            handoff_reason: Reason for handoff

        Returns:
            True if handoff criteria met
        """
        if not self._handoff_state:
            return False

        # Store handoff reason
        self._handoff_state.handoff_reason = handoff_reason
        return True

    async def execute_handoff(
        self, started_at: Optional[datetime], provider_switch_fn: Callable
    ) -> list[dict]:
        """
        Execute handoff from scanner to analyzer phase.

        Args:
            started_at: Agent start time
            provider_switch_fn: Function to switch provider to analyzer

        Returns:
            New message list for analyzer phase
        """
        if not self._handoff_state:
            return []

        # Record scanner metrics
        scanner_end_time = datetime.utcnow()
        if started_at:
            scanner_duration = int((scanner_end_time - started_at).total_seconds() * 1000)
        else:
            scanner_duration = 0
        self._handoff_state.scanner_duration_ms = scanner_duration

        # Get token usage for scanner
        usage = observability_service.get_token_usage(self.agent_id)
        self._handoff_state.scanner_tokens_used = (
            usage.prompt_tokens + usage.completion_tokens
        )

        # Broadcast handoff event
        if self._broadcast:
            self._broadcast(
                WSMessageType.PHASE_HANDOFF,
                {
                    "scanner_tokens": self._handoff_state.scanner_tokens_used,
                    "scanner_duration_ms": scanner_duration,
                    "entry_points_found": len(self._handoff_state.entry_points),
                    "sinks_found": len(self._handoff_state.dangerous_sinks),
                    "files_read": len(self._handoff_state.files_read),
                    "handoff_reason": self._handoff_state.handoff_reason,
                },
            )

        if self._log:
            self._log(
                f"Handoff: {len(self._handoff_state.entry_points)} entry points, "
                f"{len(self._handoff_state.dangerous_sinks)} sinks, "
                f"{self._handoff_state.scanner_tokens_used} tokens",
                "info",
            )

        # Switch to analyzer provider
        provider_switch_fn()

        # Build analyzer prompt with handoff context
        analyzer_prompt = format_analyzer_prompt(self._handoff_state.model_dump())

        # Reset conversation for analyzer (fresh start with context)
        messages = [
            {"role": "system", "content": analyzer_prompt},
            {
                "role": "user",
                "content": load_prompt("agents/react_analyzer_initial_user_message.md"),
            },
        ]

        return messages
