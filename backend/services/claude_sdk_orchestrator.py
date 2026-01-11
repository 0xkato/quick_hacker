"""
ClaudeSDKOrchestrator (Governor) - Turn-based orchestrator for Claude SDK sessions.

Manages Claude SDK sessions with budget enforcement, finding validation, and steering.
Implements a two-phase approach: scanner phase for discovery, analyzer phase for deep analysis.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, List, Dict


# Time budgets per scan tier (in seconds)
SCAN_TIER_BUDGETS = {
    "quick": 5 * 60,       # 5 minutes
    "medium": 15 * 60,     # 15 minutes
    "advanced": 45 * 60,   # 45 minutes
    "pro": 90 * 60,        # 90 minutes
    "ultra": 4 * 60 * 60,  # 4 hours
    "evil": 24 * 60 * 60,  # 24 hours
}

# Minimum time floors per scan tier (in seconds)
# Audit cannot complete until this time has elapsed
SCAN_TIER_FLOORS = {
    "quick": 2 * 60,       # 2 minutes minimum
    "medium": 8 * 60,      # 8 minutes
    "advanced": 30 * 60,   # 30 minutes
    "pro": 60 * 60,        # 60 minutes
    "ultra": 2 * 60 * 60,  # 2 hours
    "evil": 8 * 60 * 60,   # 8 hours
}


@dataclass
class ScanLimits:
    """Limits for a single scan turn."""
    deadline: float
    cancelled: Optional[Callable[[], bool]] = None
    max_files: int = 1000
    max_total_bytes: int = 50 * 1024 * 1024  # 50MB
    max_matches_per_file: int = 100
    max_matches_total: int = 1000

    def is_cancelled(self) -> bool:
        """Check if the scan should be cancelled."""
        if self.cancelled is not None and self.cancelled():
            return True
        if self.deadline is not None and time.monotonic() > self.deadline:
            return True
        return False


class ClaudeSDKOrchestrator:
    """
    Turn-based orchestrator for Claude SDK security audit sessions.

    Manages the audit lifecycle with:
    - Time budget enforcement per scan tier
    - Minimum time floor requirements before completion
    - Phase transitions between scanner and analyzer
    - Finding validation and steering
    """

    def __init__(
        self,
        scan_tier: str,
        on_ws_event: Callable[[Dict[str, Any]], None],
        provider: Any,
        tool_core: Any,
    ):
        """
        Initialize the orchestrator.

        Args:
            scan_tier: The tier determining time budget ("quick", "medium", "advanced", etc.)
            on_ws_event: Callback for WebSocket events
            provider: ClaudeSDKProvider instance for SDK interactions
            tool_core: Tool core for executing security tools
        """
        self.scan_tier = scan_tier.lower()
        self.on_ws_event = on_ws_event
        self.provider = provider
        self.tool_core = tool_core

        # Set budget and floor from tier
        self.budget_s = SCAN_TIER_BUDGETS.get(self.scan_tier, SCAN_TIER_BUDGETS["quick"])
        self.time_floor_s = SCAN_TIER_FLOORS.get(self.scan_tier, SCAN_TIER_FLOORS["quick"])

        # Session state
        self.start_time = time.monotonic()
        self.phase = "scanner"
        self._cancelled = False

        # Tracking
        self._findings: List[Dict[str, Any]] = []
        self._session_id: Optional[str] = None
        self._turn_count: int = 0
        self._consecutive_no_tool_turns: int = 0
        self._last_turn_time: float = 0.0

    def remaining_s(self) -> float:
        """Get remaining time budget in seconds."""
        elapsed = time.monotonic() - self.start_time
        return max(0.0, self.budget_s - elapsed)

    def elapsed_s(self) -> float:
        """Get elapsed time since start in seconds."""
        return time.monotonic() - self.start_time

    def time_floor_satisfied(self) -> bool:
        """Check if the minimum time floor has been met."""
        return self.elapsed_s() >= self.time_floor_s

    def make_fresh_limits(self) -> ScanLimits:
        """
        Create new ScanLimits with deadline at 25% of remaining budget.

        This ensures individual turns don't consume the entire budget,
        allowing for multiple turns and phase transitions.
        """
        remaining = self.remaining_s()
        deadline = time.monotonic() + (remaining * 0.25)
        return ScanLimits(
            deadline=deadline,
            cancelled=lambda: self._cancelled,
        )

    def cancel(self) -> None:
        """Cancel the current audit session."""
        self._cancelled = True
        if self.provider is not None:
            self.provider.interrupt()

    async def run_audit(
        self,
        initial_prompt: str,
        resume_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the main audit loop.

        Args:
            initial_prompt: The initial prompt to start the audit
            resume_session_id: Optional session ID to resume from

        Returns:
            Dict containing audit results, findings, and metadata
        """
        print(f"[SDK Orchestrator] Starting audit, budget={self.budget_s}s, floor={self.time_floor_s}s")
        self._session_id = resume_session_id
        current_prompt = initial_prompt
        error_message: Optional[str] = None

        while not self._cancelled and self.remaining_s() > 0:
            self._turn_count += 1
            turn_start = time.monotonic()

            # Detect rapid spinning (turns completing in < 1 second without tool calls)
            if self._last_turn_time > 0:
                turn_interval = turn_start - self._last_turn_time
                if turn_interval < 1.0 and self._consecutive_no_tool_turns > 0:
                    print(f"[SDK Orchestrator] WARNING: Rapid turn ({turn_interval:.2f}s), no tools for {self._consecutive_no_tool_turns} turns")

                    # If we've had 10+ rapid turns without tool usage, something is wrong
                    if self._consecutive_no_tool_turns >= 10:
                        error_message = "SDK not using tools - check tool configuration"
                        print(f"[SDK Orchestrator] ERROR: {error_message}")
                        self._emit_event("error", {
                            "message": error_message,
                            "consecutive_no_tool_turns": self._consecutive_no_tool_turns,
                        })
                        break

            self._last_turn_time = turn_start
            print(f"[SDK Orchestrator] Turn {self._turn_count}, remaining={self.remaining_s():.1f}s")

            # Create fresh limits for this turn
            limits = self.make_fresh_limits()

            # Get the appropriate policy for current phase
            if self.phase == "scanner":
                policy = self._get_scanner_policy()
            else:
                policy = self._get_analyzer_policy()

            # Execute turn with provider
            try:
                response = await self._execute_turn(current_prompt, policy, limits)
                tool_call_count = len(response.get('tool_calls', []))
                content_len = len(response.get('content', ''))
                print(f"[SDK Orchestrator] Turn response: content_len={content_len}, tool_calls={tool_call_count}")

                # Track consecutive turns without tool calls
                if tool_call_count == 0:
                    self._consecutive_no_tool_turns += 1
                else:
                    self._consecutive_no_tool_turns = 0

            except Exception as e:
                print(f"[SDK Orchestrator] Turn failed with error: {e}")
                import traceback
                traceback.print_exc()
                error_message = str(e)
                self._emit_event("error", {"message": error_message})
                break

            # Check if Claude indicates completion
            if self._claude_says_done(response.get("content", "")):
                # Validate findings before allowing completion
                validation = self._validate_findings()
                if validation.get("is_valid") and self.time_floor_satisfied():
                    break
                else:
                    # Steer back to continue work
                    current_prompt = self._build_steering_prompt()
                    continue

            # Check if we should hand off to analyzer phase
            if self._should_handoff():
                self._do_handoff()
                current_prompt = self._build_analyzer_prompt()
            else:
                current_prompt = self._build_continue_prompt()

        return {
            "success": (not self._cancelled) and (error_message is None),
            "error_message": error_message,
            "findings": self._findings,
            "phase": self.phase,
            "elapsed_s": self.elapsed_s(),
            "turn_count": self._turn_count,
            "session_id": self._session_id,
        }

    async def _execute_turn(
        self,
        prompt: str,
        policy: str,
        limits: ScanLimits,
    ) -> Dict[str, Any]:
        """Execute a single turn with the Claude SDK provider.

        Integrates with ClaudeSDKProvider to run the actual SDK agent loop.

        Args:
            prompt: User prompt for this turn
            policy: System policy (scanner or analyzer)
            limits: Scan limits for this turn

        Returns:
            Dict with 'content' (text response) and 'tool_calls' (list of calls)
        """
        if self.provider is None:
            print("[SDK Orchestrator] ERROR: No provider configured!")
            self._emit_event("error", {"message": "No provider configured"})
            return {"content": "", "tool_calls": []}

        # Start session on first turn
        if self._turn_count == 1:
            print(f"[SDK Orchestrator] Starting session (first turn)...")
            try:
                self._session_id = await self.provider.start_session(
                    audit_policy=policy,
                    resume_session_id=self._session_id,
                )
                print(f"[SDK Orchestrator] Session started: {self._session_id}")
                self._emit_event("session_started", {"session_id": self._session_id})
            except Exception as e:
                print(f"[SDK Orchestrator] Failed to start session: {e}")
                import traceback
                traceback.print_exc()
                self._emit_event("error", {"message": f"Failed to start session: {e}"})
                raise

        # Collect response content and tool calls from events
        content_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        turn_error: Optional[str] = None

        def on_event(event: Dict[str, Any]) -> None:
            """Process SDK events and collect response data."""
            nonlocal turn_error
            event_type = event.get("type", "")

            # Emit all events to WebSocket
            self._emit_event(event_type, event)

            # Collect text content
            if event_type == "agent_text":
                text = event.get("text", "")
                if text:
                    content_parts.append(text)

            # Collect tool calls
            elif event_type == "tool_call":
                tool_calls.append({
                    "id": event.get("id", ""),
                    "name": event.get("name", ""),
                    "args": event.get("args", {}),
                })

            elif event_type == "turn_complete":
                if event.get("is_error"):
                    turn_error = str(event.get("result") or "Claude SDK turn failed")

            # Extract findings from tool results
            elif event_type == "tool_result":
                if event.get("is_error"):
                    return

                raw_result = event.get("result")
                parsed: Any = None

                if isinstance(raw_result, dict):
                    parsed = raw_result
                else:
                    text: str | None = None
                    if isinstance(raw_result, str):
                        text = raw_result
                    elif isinstance(raw_result, list):
                        parts: list[str] = []
                        for item in raw_result:
                            if not isinstance(item, dict):
                                continue
                            if item.get("type") != "text":
                                continue
                            block_text = item.get("text")
                            if isinstance(block_text, str):
                                parts.append(block_text)
                        if parts:
                            text = "\n".join(parts)

                    if text:
                        candidate = text.lstrip()
                        if candidate.startswith("{") or candidate.startswith("["):
                            try:
                                parsed = json.loads(text)
                            except json.JSONDecodeError:
                                parsed = None

                # Recognize our ToolCore.report_finding output.
                if isinstance(parsed, dict) and isinstance(parsed.get("finding"), dict):
                    self._findings.append(parsed["finding"])

        try:
            # Run turn with event callback
            await self.provider.run_turn(prompt, on_event=on_event)
        except Exception as e:
            self._emit_event("error", {"message": f"Turn failed: {e}"})
            raise

        if turn_error:
            raise RuntimeError(self._map_turn_error(turn_error))

        return {
            "content": "".join(content_parts),
            "tool_calls": tool_calls,
        }

    @staticmethod
    def _map_turn_error(turn_error: str) -> str:
        """Rewrite common Claude Code auth failures into actionable guidance."""
        message = str(turn_error or "").strip()
        lower = message.lower()

        if "please run /login" in lower or ("invalid api key" in lower and "/login" in lower):
            return (
                "Claude Code authentication required. "
                "Run `claude setup-token` (Docker: `docker compose exec -it backend claude setup-token`) "
                "or set `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`."
            )

        return message

    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit a WebSocket event."""
        if self.on_ws_event:
            self.on_ws_event({"type": event_type, **data})

    def _validate_findings(self) -> Dict[str, Any]:
        """
        Validate the collected findings.

        Checks that findings have required fields and meet quality thresholds.
        """
        if not self._findings:
            return {"is_valid": True, "message": "No findings to validate"}

        # Basic validation - check required fields
        valid_findings = []
        for finding in self._findings:
            if all(k in finding for k in ("title", "severity")):
                valid_findings.append(finding)

        return {
            "is_valid": len(valid_findings) == len(self._findings),
            "total": len(self._findings),
            "valid": len(valid_findings),
            "message": f"Validated {len(valid_findings)}/{len(self._findings)} findings",
        }

    def _should_handoff(self) -> bool:
        """
        Determine if we should hand off from scanner to analyzer phase.

        Hand off when:
        - We're in scanner phase
        - We've accumulated findings to analyze
        - We've used more than 50% of the time budget
        """
        if self.phase != "scanner":
            return False

        if not self._findings:
            return False

        # Hand off after 50% of budget or if we have many findings
        time_ratio = self.elapsed_s() / self.budget_s
        if time_ratio > 0.5:
            return True

        if len(self._findings) >= 10:
            return True

        return False

    def _do_handoff(self) -> None:
        """Perform the handoff from scanner to analyzer phase."""
        self.phase = "analyzer"
        self._emit_event("phase_change", {"phase": "analyzer"})

    def _claude_says_done(self, response: str) -> bool:
        """
        Check if Claude's response indicates completion.

        Looks for completion indicators in the response text.
        """
        if not response:
            return False

        completion_indicators = [
            "audit complete",
            "scan complete",
            "analysis complete",
            "no more findings",
            "investigation complete",
        ]

        response_lower = response.lower()
        return any(indicator in response_lower for indicator in completion_indicators)

    def _build_continue_prompt(self) -> str:
        """Build prompt to continue the current phase."""
        remaining_mins = self.remaining_s() / 60
        return (
            f"Continue your security analysis. "
            f"You have approximately {remaining_mins:.1f} minutes remaining. "
            f"Focus on high-priority findings and unexplored areas."
        )

    def _build_steering_prompt(self) -> str:
        """Build prompt to steer Claude back to work when trying to complete early."""
        floor_remaining = self.time_floor_s - self.elapsed_s()
        if floor_remaining > 0:
            return (
                f"The audit cannot complete yet. "
                f"Minimum investigation time not met ({floor_remaining:.0f}s remaining). "
                f"Please continue analyzing the codebase for security issues. "
                f"Consider: authentication flows, input validation, data exposure, and dependency risks."
            )
        else:
            return (
                f"Please continue the analysis. "
                f"Ensure you've thoroughly investigated all critical areas before completing. "
                f"Remaining budget: {self.remaining_s():.0f}s."
            )

    def _build_analyzer_prompt(self) -> str:
        """Build prompt for transitioning to analyzer phase."""
        finding_count = len(self._findings)
        return (
            f"Transitioning to deep analysis phase. "
            f"You have {finding_count} findings to analyze in depth. "
            f"For each finding, verify its validity, assess exploitability, "
            f"and provide detailed remediation guidance. "
            f"Prioritize critical and high severity findings."
        )

    def _get_scanner_policy(self) -> str:
        """Get the system policy for scanner phase."""
        return (
            "You are a security scanner focused on discovering vulnerabilities. "
            "Systematically scan the codebase for: "
            "1. Hardcoded secrets and credentials "
            "2. Injection vulnerabilities (SQL, command, XSS) "
            "3. Authentication and authorization flaws "
            "4. Insecure cryptographic usage "
            "5. Dangerous dependencies "
            "Report each finding with severity, location, and brief description."
        )

    def _get_analyzer_policy(self) -> str:
        """Get the system policy for analyzer phase."""
        return (
            "You are a security analyst performing deep analysis of findings. "
            "For each finding: "
            "1. Verify the vulnerability is real (not a false positive) "
            "2. Assess exploitability and impact "
            "3. Trace data flows to understand attack surface "
            "4. Provide specific remediation steps "
            "5. Rate confidence in the finding "
            "Be thorough but efficient with remaining time."
        )
