"""Dispatch tools for Overseer to spawn sub-agents."""

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agents.deep_audit.dispatcher import WaveDispatcher, WavePlan, DispatchTask


# These will be set by the Overseer when initializing tools
_dispatcher: "WaveDispatcher" = None
_current_wave_id: int = 0


def set_dispatcher(dispatcher: "WaveDispatcher"):
    """Set the dispatcher instance for tools to use."""
    global _dispatcher
    _dispatcher = dispatcher


def set_wave_id(wave_id: int):
    """Set the current wave ID."""
    global _current_wave_id
    _current_wave_id = wave_id


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

        # Dispatch and wait
        result = await _dispatcher.dispatch_wave(wave_plan)

        # Format results
        return json.dumps({
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

        result = await _dispatcher.dispatch_single(task)

        return json.dumps({
            "task_id": result.task_id,
            "agent_type": result.agent_type,
            "status": result.status,
            "output_path": result.output_path,
            "error": result.error,
            "tokens_used": result.tokens_used,
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
