"""Deep Audit Supervisor using LangGraph + Deep Agents."""

import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from langgraph.graph import StateGraph, END

from agents.base_agent import BaseAgent
from agents.deep_audit.state import SupervisorState
from agents.deep_audit.nodes import (
    init_state,
    build_scopes,
    dispatch_workers,
    merge_signals,
    prioritize_cases,
    dispatch_auditor,
    check_budget,
    finalize,
)
from models.schemas import AgentCreateRequest, AgentStatus, Finding, WSMessage


class DeepAuditSupervisor(BaseAgent):
    """
    Deep Audit Supervisor using LangGraph orchestration.

    Replaces ReAct loop with segmented multi-agent architecture:
    - Supervisor (this class) orchestrates via StateGraph
    - Worker subagents gather context and emit signals
    - Auditor subagent verifies signals and promotes findings
    """

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
    ):
        """Initialize supervisor."""
        self.id = str(uuid.uuid4())
        self.repo_id = request.repo_id
        self.repo_path = Path(repo_path)
        self.request = request
        self.on_message = on_message or (lambda msg: None)

        self.status = AgentStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None

        self.findings: list[Finding] = []
        self.files_analyzed: list[str] = []

        # Build LangGraph
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build LangGraph StateGraph for audit workflow."""
        workflow = StateGraph(SupervisorState)

        # Add nodes
        workflow.add_node("init_state", init_state)
        workflow.add_node("build_scopes", build_scopes)
        workflow.add_node("dispatch_workers", dispatch_workers)
        workflow.add_node("merge_signals", merge_signals)
        workflow.add_node("prioritize_cases", prioritize_cases)
        workflow.add_node("dispatch_auditor", dispatch_auditor)
        workflow.add_node("finalize", finalize)

        # Add edges
        workflow.set_entry_point("init_state")
        workflow.add_edge("init_state", "build_scopes")
        workflow.add_edge("build_scopes", "dispatch_workers")
        workflow.add_edge("dispatch_workers", "merge_signals")
        workflow.add_edge("merge_signals", "prioritize_cases")
        workflow.add_edge("prioritize_cases", "dispatch_auditor")

        # Conditional edge from dispatch_auditor
        workflow.add_conditional_edges(
            "dispatch_auditor",
            check_budget,
            {
                "continue": "dispatch_workers",  # Loop back
                "finalize": "finalize",
            }
        )

        workflow.add_edge("finalize", END)

        return workflow.compile()

    async def analyze(self):
        """
        Perform the actual analysis (required by BaseAgent).

        For DeepAuditSupervisor, the analysis is performed by running
        the LangGraph workflow which orchestrates worker and auditor subagents.
        """
        # Initialize state
        initial_state = SupervisorState(
            project_id=self.repo_id,
            scan_tier=self.request.scan_tier or "quick",
            deadline=0.0,  # Will be set by init_state node
        )

        # Run graph
        final_state = self.graph.invoke(initial_state)

        # TODO: Collect findings from final state
        # For now, findings will be collected through BaseAgent.add_finding()
        # called by subagents or nodes

    async def run(self) -> list[Finding]:
        """
        Run the audit.

        Returns:
            List of Finding objects
        """
        self.status = AgentStatus.RUNNING
        self.started_at = datetime.utcnow()

        try:
            await self.analyze()

            self.status = AgentStatus.COMPLETED
            self.completed_at = datetime.utcnow()

            return self.findings

        except Exception as e:
            self.status = AgentStatus.FAILED
            self.error_message = str(e)
            raise

    def pause(self):
        """Pause the audit."""
        self.status = AgentStatus.PAUSED

    def resume(self):
        """Resume the audit."""
        self.status = AgentStatus.RUNNING

    def cancel(self):
        """Cancel the audit."""
        self.status = AgentStatus.CANCELLED
