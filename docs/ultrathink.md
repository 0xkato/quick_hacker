# Ultrathink: Hierarchical Verification Cascade

## Overview

Ultrathink is a provider-agnostic extended thinking architecture for security vulnerability research. It maximizes AI model cognitive depth through a hierarchical verification cascade where findings must survive progressively harder scrutiny.

## Philosophy

Standard inference gives the model ~500ms to "think" before outputting. Ultrathink gives it **60+ seconds of cognitive runway** to:

- Generate and test hypotheses
- Backtrack when reasoning hits dead ends
- Verify its own claims against evidence
- Argue against itself before committing

## The Cascade

```
Finding -> Triage -> Deep Analysis -> Devil's Advocate -> Proof Generator -> Final Gate -> Report
             |           |                |                 |              |
           FAST      THOROUGH        ADVERSARIAL        CONCRETE       REPUTATION
```

### Gate 1: Triage (5s)
Quick filter for obvious non-issues. Uses minimal thinking budget.

### Gate 2: Deep Analysis (180s)
Thorough source-to-sink verification with maximum thinking budget.

### Gate 3: Devil's Advocate (120s)
Actively argues AGAINST the finding. Maximum adversarial strength.

### Gate 4: Proof Generator (90s)
Must produce concrete exploit proof or admit inability.

### Gate 5: Final Gate (60s)
"Would you stake your professional reputation on this?"

## Thinking Modes

### Native (Claude)
Uses Claude's built-in extended thinking with `thinking` blocks.

### Simulated (GPT-4)
Simulates extended thinking via chain-of-thought prompting.

### Structured (Open Source)
Uses highly structured reasoning prompts for models without native thinking.

## Configuration

```python
from ultrathink import UltrathinkConfig, ThinkingMode

config = UltrathinkConfig(
    thinking_mode=ThinkingMode.AUTO,  # Auto-detect based on model
    min_thinking_tokens=10000,
    max_thinking_tokens=50000,
    capture_full_trace=True,
    expose_thinking_to_user=True,
)
```

## Usage

```python
from ultrathink import UltrathinkCascade
from models.schemas import Finding

cascade = UltrathinkCascade(config=config)

result = await cascade.evaluate(
    finding=finding,
    code_context=code,
    provider=provider,
    model="claude-opus-4-5-20251101",
)

if result.final_verdict:
    print(f"VERIFIED with {result.final_confidence:.0%} confidence")
else:
    print(f"REJECTED by {result.rejected_by}: {result.rejection_reason}")
```

## Transparency

Full reasoning traces are captured and exposed:

```python
for trace in result.reasoning_traces:
    print(trace)  # Full thinking from each gate
```

## Integration

Use `UltrathinkAgent` as a drop-in replacement for other agents:

```python
from agents import UltrathinkAgent
from models.schemas import AgentCreateRequest

request = AgentCreateRequest(
    repo_id="your-repo-id",
    agent_type=AgentType.ULTRATHINK,
    provider_config=provider_config,
)

agent = UltrathinkAgent(request, repo_path, on_message=emit)
findings = await agent.run()
```

## WebSocket Events

The ultrathink cascade emits real-time events:

- `ultrathink_cascade_start` - Cascade begins for a finding
- `ultrathink_gate_start` - Gate evaluation begins
- `ultrathink_gate_complete` - Gate evaluation complete (pass/fail)
- `ultrathink_thinking_update` - Real-time thinking stream
- `ultrathink_cascade_complete` - Final verdict

## Architecture

```
ultrathink/
  __init__.py       # Package exports
  config.py         # UltrathinkConfig, GateConfig
  thinking.py       # ThinkingEngine (native/simulated/structured)
  gates.py          # 5 verification gates
  cascade.py        # UltrathinkCascade orchestrator
  events.py         # WebSocket event emitter

agents/
  ultrathink_agent.py  # Full agent integration

frontend/components/UltrathinkPanel/
  UltrathinkPanel.tsx  # Main visualization
  GateProgress.tsx     # Gate progress indicator
  ThinkingTrace.tsx    # Reasoning viewer
```

## Test Coverage

```bash
# Run all ultrathink tests
cd backend && python -m pytest tests/ultrathink/ -v

# Run integration tests
cd backend && python -m pytest tests/integration/ -v
```
