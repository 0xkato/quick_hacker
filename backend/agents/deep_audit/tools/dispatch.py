"""Dispatch tools for Overseer to spawn sub-agents."""

import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agents.deep_audit.dispatcher import WaveDispatcher, WavePlan, DispatchTask
    from agents.deep_audit.foundation import FoundationContext


# These will be set by the Overseer when initializing tools
_dispatcher: "WaveDispatcher" = None
_current_wave_id: int = 0
_foundation_context: Optional["FoundationContext"] = None


def set_dispatcher(dispatcher: "WaveDispatcher"):
    """Set the dispatcher instance for tools to use."""
    global _dispatcher
    _dispatcher = dispatcher


def set_wave_id(wave_id: int):
    """Set the current wave ID."""
    global _current_wave_id
    _current_wave_id = wave_id


def set_foundation_context(context: "FoundationContext"):
    """Set the Foundation Context from Foundation Phase."""
    global _foundation_context
    _foundation_context = context


def get_foundation_context() -> Optional["FoundationContext"]:
    """Get the current Foundation Context."""
    return _foundation_context


async def dispatch_wave(wave_plan_json: str) -> str:
    """Dispatch a wave of sub-agents in parallel.

    This tool takes a JSON wave plan and dispatches all tasks in parallel,
    waiting for all to complete before returning results.

    Args:
        wave_plan_json: JSON string containing wave plan with tasks:
            {
                "wave_id": 1,
                "rationale": "Why these tasks",
                "tasks": [
                    {
                        "agent_type": "RepoProfiler",
                        "objective": "Map the repository structure",
                        "scope": "/",
                        "inputs": [],
                        "deliverable": "/memories/repo_profile.json",
                        "time_budget": 300
                    },
                    ...
                ]
            }

    Returns:
        JSON string with results for all tasks
    """
    if _dispatcher is None:
        return json.dumps({"error": "Dispatcher not initialized"})

    try:
        from agents.deep_audit.dispatcher import WavePlan, DispatchTask

        plan_data = json.loads(wave_plan_json)

        # Build WavePlan
        tasks = [
            DispatchTask(
                agent_type=t["agent_type"],
                objective=t["objective"],
                scope=t.get("scope", "/"),
                inputs=t.get("inputs", []),
                deliverable=t["deliverable"],
                success_criteria=t.get("success_criteria", ""),
                time_budget=t.get("time_budget", 300),
                constraints=t.get("constraints", ""),
            )
            for t in plan_data.get("tasks", [])
        ]

        wave_plan = WavePlan(
            wave_id=plan_data.get("wave_id", _current_wave_id),
            tasks=tasks,
            rationale=plan_data.get("rationale", ""),
        )

        # Dispatch and wait - pass Foundation Context if available
        result = await _dispatcher.dispatch_wave(wave_plan, foundation_context=_foundation_context)

        # Format results
        context_applied = _foundation_context is not None
        return json.dumps({
            "foundation_context_applied": context_applied,
            "wave_id": result.wave_id,
            "all_succeeded": result.all_succeeded,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "results": [
                {
                    "task_id": r.task_id,
                    "agent_type": r.agent_type,
                    "status": r.status,
                    "output_path": r.output_path,
                    "error": r.error,
                    "tokens_used": r.tokens_used,
                }
                for r in result.results
            ]
        }, indent=2)

    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


async def dispatch_agent(
    agent_type: str,
    objective: str,
    scope: str,
    deliverable: str,
    inputs: str = "",
    time_budget: int = 300,
) -> str:
    """Dispatch a single sub-agent (convenience for one-off tasks).

    Args:
        agent_type: Type of agent (RepoProfiler, SinkHunter, etc.)
        objective: What the agent should accomplish
        scope: Directory/module to focus on
        deliverable: Expected output path in /memories/
        inputs: Comma-separated list of input artifact paths
        time_budget: Seconds allowed for this task

    Returns:
        JSON string with task result
    """
    if _dispatcher is None:
        return json.dumps({"error": "Dispatcher not initialized"})

    try:
        from agents.deep_audit.dispatcher import DispatchTask

        task = DispatchTask(
            agent_type=agent_type,
            objective=objective,
            scope=scope,
            inputs=[i.strip() for i in inputs.split(",") if i.strip()] if inputs else [],
            deliverable=deliverable,
            time_budget=time_budget,
        )

        # Pass Foundation Context if available
        result = await _dispatcher.dispatch_single(task, foundation_context=_foundation_context)

        return json.dumps({
            "task_id": result.task_id,
            "agent_type": result.agent_type,
            "status": result.status,
            "output_path": result.output_path,
            "error": result.error,
            "tokens_used": result.tokens_used,
            "foundation_context_applied": _foundation_context is not None,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


# Tool definitions for ReactAgent
DISPATCH_WAVE_TOOL = {
    "name": "dispatch_wave",
    "description": """Dispatch a wave of sub-agents in parallel. Takes a JSON wave plan and runs all tasks simultaneously, waiting for all to complete.

Example wave_plan_json:
{
    "wave_id": 1,
    "rationale": "Initial reconnaissance",
    "tasks": [
        {"agent_type": "RepoProfiler", "objective": "Map repo structure", "scope": "/", "deliverable": "/memories/repo_profile.json"},
        {"agent_type": "EntrypointHunter", "objective": "Find HTTP routes", "scope": "/backend", "deliverable": "/memories/scopes/backend/entrypoints.json"}
    ]
}""",
    "input_schema": {
        "type": "object",
        "properties": {
            "wave_plan_json": {
                "type": "string",
                "description": "JSON string containing the wave plan with tasks array"
            }
        },
        "required": ["wave_plan_json"]
    }
}

async def dispatch_foundation_phase() -> str:
    """Dispatch the Foundation Phase: RepoProfiler, ScopeMapper, ThreatModeler in parallel.

    This MUST be called before any hunting waves. It builds the Foundation Context
    that all subsequent agents will use for filtering and prioritization.

    Returns:
        JSON string with Foundation Phase results and context summary
    """
    if _dispatcher is None:
        return json.dumps({"error": "Dispatcher not initialized"})

    try:
        result, foundation_context = await _dispatcher.dispatch_foundation_phase()

        response = {
            "wave_id": result.wave_id,
            "all_succeeded": result.all_succeeded,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "results": [
                {
                    "task_id": r.task_id,
                    "agent_type": r.agent_type,
                    "status": r.status,
                    "output_path": r.output_path,
                    "error": r.error,
                }
                for r in result.results
            ],
            "foundation_context_built": foundation_context is not None,
        }

        if foundation_context:
            # Store Foundation Context for subsequent waves
            global _foundation_context
            _foundation_context = foundation_context

            response["foundation_summary"] = {
                "languages": foundation_context.repo_profile.languages,
                "frameworks": foundation_context.repo_profile.frameworks,
                "security_critical_paths": foundation_context.scope_map.security_critical[:5],
                "test_code_patterns": foundation_context.scope_map.test_code[:3],
                "attacker_capabilities": [c.value for c in foundation_context.threat_model.attacker_capabilities],
                "in_scope_paths": foundation_context.threat_model.in_scope_paths[:5],
            }
            # Phase transition: Foundation complete, ready for Hunting
            response["next_phase"] = "hunting"
            response["phase_instruction"] = "Foundation Phase complete. You may now dispatch Hunting waves (EntrypointHunter, SinkHunter)."
        else:
            response["next_phase"] = "foundation"
            response["phase_instruction"] = "Foundation Phase failed. Check errors and retry."

        return json.dumps(response, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


DISPATCH_FOUNDATION_PHASE_TOOL = {
    "name": "dispatch_foundation_phase",
    "description": """MANDATORY: Run Foundation Phase before any hunting.

This dispatches RepoProfiler, ScopeMapper, and ThreatModeler in parallel to build the Foundation Context.
All subsequent agents will use this context for scope filtering and threat model awareness.

Returns the Foundation Context summary including:
- Languages and frameworks detected
- Security-critical paths to prioritize
- Test/vendor code patterns to ignore
- Attacker capabilities for threat modeling

ALWAYS call this first before dispatch_wave for hunting.""",
    "input_schema": {
        "type": "object",
        "properties": {},
        "required": []
    }
}


DISPATCH_AGENT_TOOL = {
    "name": "dispatch_agent",
    "description": "Dispatch a single sub-agent for a one-off task. Use dispatch_wave for multiple parallel tasks.",
    "input_schema": {
        "type": "object",
        "properties": {
            "agent_type": {
                "type": "string",
                "description": "Type of agent: RepoProfiler, ScopeMapper, EntrypointHunter, SinkHunter, DataflowTracer, ThreatModeler, AuthBoundaryMapper, Triager, Auditor, Reproducer"
            },
            "objective": {
                "type": "string",
                "description": "What the agent should accomplish"
            },
            "scope": {
                "type": "string",
                "description": "Directory or module path to focus on"
            },
            "deliverable": {
                "type": "string",
                "description": "Expected output path in /memories/"
            },
            "inputs": {
                "type": "string",
                "description": "Comma-separated list of input artifact paths (optional)"
            },
            "time_budget": {
                "type": "integer",
                "description": "Seconds allowed for this task (default 300)"
            }
        },
        "required": ["agent_type", "objective", "scope", "deliverable"]
    }
}
