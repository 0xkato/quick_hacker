"""WebSocket event emitters for ultrathink cascade."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable, Any

from models.schemas import WSMessage, WSMessageType, UltrathinkGate
from .gates import GateResult
from .cascade import CascadeResult


@dataclass
class UltrathinkEventEmitter:
    """Emits WebSocket events for ultrathink cascade progress."""

    agent_id: str
    on_message: Optional[Callable[[WSMessage], None]] = None

    def emit(self, msg_type: WSMessageType, data: dict):
        """Emit a WebSocket message."""
        if self.on_message:
            msg = WSMessage(
                type=msg_type,
                agent_id=self.agent_id,
                data=data,
                timestamp=datetime.utcnow(),
            )
            self.on_message(msg)

    def emit_cascade_start(self, finding_id: str, finding_title: str):
        """Emit cascade start event."""
        self.emit(
            WSMessageType.ULTRATHINK_CASCADE_START,
            {
                "finding_id": finding_id,
                "finding_title": finding_title,
                "gates": [g.value for g in UltrathinkGate],
            }
        )

    def emit_gate_start(self, gate: UltrathinkGate, finding_id: str):
        """Emit gate start event."""
        self.emit(
            WSMessageType.ULTRATHINK_GATE_START,
            {
                "gate": gate.value,
                "finding_id": finding_id,
            }
        )

    def emit_gate_complete(self, result: GateResult, finding_id: str):
        """Emit gate completion event."""
        self.emit(
            WSMessageType.ULTRATHINK_GATE_COMPLETE,
            {
                "gate": result.gate.value,
                "finding_id": finding_id,
                "passed": result.passed,
                "confidence": result.confidence,
                "reasoning": result.reasoning,
                "duration_ms": result.duration_ms,
                "thinking_preview": result.full_trace[:500] if result.full_trace else None,
            }
        )

    def emit_thinking_update(
        self,
        gate: UltrathinkGate,
        finding_id: str,
        thinking_chunk: str,
        tokens_so_far: int,
    ):
        """Emit real-time thinking update (for streaming)."""
        self.emit(
            WSMessageType.ULTRATHINK_THINKING_UPDATE,
            {
                "gate": gate.value,
                "finding_id": finding_id,
                "thinking_chunk": thinking_chunk,
                "tokens_so_far": tokens_so_far,
            }
        )

    def emit_cascade_complete(self, result: CascadeResult):
        """Emit cascade completion event."""
        self.emit(
            WSMessageType.ULTRATHINK_CASCADE_COMPLETE,
            {
                "finding_id": result.finding.id,
                "final_verdict": result.final_verdict,
                "final_confidence": result.final_confidence,
                "rejected_by": result.rejected_by.value if result.rejected_by else None,
                "rejection_reason": result.rejection_reason,
                "total_thinking_tokens": result.total_thinking_tokens,
                "total_duration_ms": result.total_duration_ms,
                "gates_passed": sum(1 for gr in result.gate_results if gr.passed),
                "gates_total": len(result.gate_results),
            }
        )
