# Signal Routing Flow Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement proper signal routing: Decider → FamilyCoordinator → Specialist → Triager

**Architecture:** Each signal is processed individually through a 4-stage pipeline. Decider decides if worth investigating, FamilyCoordinator picks specialists and provides context, Specialist validates technically, Triager classifies based on threat model.

**Tech Stack:** Python, Claude CLI sub-agents, async/await

**Bead:** qh-c77

---

## Task 1: Add Signal Routing Method Skeleton

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py`

**Step 1: Add the routing method signature**

After `_dispatch_specialists()` method (around line 1145), add:

```python
async def _route_signal_through_pipeline(self, signal: dict) -> Optional[dict]:
    """Route a single signal through Decider → FamilyCoordinator → Specialist → Triager.

    Args:
        signal: A signal dict from SinkHunter with keys like signal_id, category, file_path, etc.

    Returns:
        Finding dict if signal is verified as vulnerability, None if dismissed.
    """
    signal_id = signal.get("signal_id", f"sig-{hash(str(signal)) % 10000}")

    # Stage 1: Decider
    decider_result = await self._run_decider(signal)
    if not decider_result or decider_result.get("decision") == "dismiss":
        return None

    # Stage 2: FamilyCoordinator
    coordinator_result = await self._run_family_coordinator(signal, decider_result)
    if not coordinator_result:
        return None

    # Stage 3: Specialist
    specialist_result = await self._run_specialist(signal, coordinator_result)

    # Stage 4: Triager (even if specialist failed/errored)
    finding = await self._run_triager(signal, specialist_result)

    return finding
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(deep_audit): add signal routing pipeline skeleton"
```

---

## Task 2: Implement Decider Stage

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py`

**Step 1: Add _run_decider method**

```python
async def _run_decider(self, signal: dict) -> Optional[dict]:
    """Stage 1: Decider evaluates if signal is worth investigating.

    Decider looks at each signal individually and decides:
    - investigate: Signal looks promising, route to specialist
    - dismiss: Signal is clearly not a vulnerability (e.g., test code, dead code)

    Args:
        signal: Signal dict from hunter

    Returns:
        Dict with decision and routing info, or None on error
    """
    from agents.deep_audit.subagents import get_decider_prompt

    signal_context = json.dumps(signal, indent=2)

    # Build objective with signal data
    objective = f"""Evaluate this signal and decide if it's worth investigating.

## Signal to Evaluate
```json
{signal_context}
```

Decide:
- "investigate" if this looks like a real potential vulnerability
- "dismiss" if this is clearly not a vulnerability (test code, unreachable, etc.)

Output your decision as JSON."""

    try:
        result = await self.dispatcher.dispatch_single_agent(
            agent_type="Decider",
            objective=objective,
            scope=self.repo_path_str,
            deliverable=f"/memories/routing/decider_{signal.get('signal_id', 'unknown')}.json",
            time_budget=60,  # 1 minute max for decision
        )

        if result and result.output:
            return self._extract_json_from_output(result.output)
        return None

    except Exception as e:
        print(f"[Overseer] Decider failed for signal: {e}")
        # On error, default to investigate (don't drop signals)
        return {"decision": "investigate", "error": str(e)}
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(deep_audit): implement Decider stage for signal routing"
```

---

## Task 3: Implement FamilyCoordinator Stage

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py`

**Step 1: Add _run_family_coordinator method**

```python
async def _run_family_coordinator(self, signal: dict, decider_result: dict) -> Optional[dict]:
    """Stage 2: FamilyCoordinator picks specialists and provides context.

    IMPORTANT: FamilyCoordinator provides CODE CONTEXT to specialists,
    NOT the threat model. The threat model is only used by Triager.

    Args:
        signal: Signal dict from hunter
        decider_result: Output from Decider stage

    Returns:
        Dict with specialist assignment and context, or None on error
    """
    from agents.deep_audit.subagents import get_family_coordinator_prompt
    from agents.deep_audit.specialists.registry import (
        get_family_for_signal,
        SpecialistRegistry,
    )
    from agents.deep_audit.foundation import SignalCategory

    # Determine the family for this signal
    category_str = signal.get("category", signal.get("vulnerability_type", "unknown"))
    try:
        category = SignalCategory(category_str.lower().replace(" ", "_").replace("-", "_"))
        family = get_family_for_signal(category)
    except (ValueError, KeyError):
        family = SpecialistFamily.API_DESIGN  # Fallback

    # Get specialists in this family
    registry = SpecialistRegistry()
    family_specialists = registry.get_by_family(family)
    specialist_list = "\n".join([f"- {s.id}: {s.proficiency}" for s in family_specialists])

    signal_context = json.dumps(signal, indent=2)

    objective = f"""Coordinate specialist assignment for this signal.

## Signal
```json
{signal_context}
```

## Family: {family.value}

## Available Specialists
{specialist_list}

Pick the most appropriate specialist(s) and provide code context they need.
DO NOT include threat model - that's for Triager only.

Output as JSON with: primary_specialist, secondary_specialist (optional), context_for_specialist"""

    try:
        result = await self.dispatcher.dispatch_single_agent(
            agent_type="FamilyCoordinator",
            objective=objective,
            scope=self.repo_path_str,
            deliverable=f"/memories/routing/coordinator_{signal.get('signal_id', 'unknown')}.json",
            time_budget=90,  # 1.5 minutes
        )

        if result and result.output:
            coord_result = self._extract_json_from_output(result.output)
            if coord_result:
                coord_result["family"] = family.value
            return coord_result
        return None

    except Exception as e:
        print(f"[Overseer] FamilyCoordinator failed: {e}")
        # On error, use default specialist for category
        specialists = registry.get_for_category(category) if category else []
        return {
            "primary_specialist": specialists[0].id if specialists else "generic_auditor",
            "family": family.value,
            "context_for_specialist": "Error getting coordinator context",
            "error": str(e),
        }
```

**Step 2: Add import for SpecialistFamily at top of file**

Add to imports around line 58-62:

```python
from agents.deep_audit.specialists.registry import (
    SpecialistRegistry,
    SpecialistFamily,
    get_family_for_signal,
    get_specialists_for_signal,
)
```

**Step 3: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(deep_audit): implement FamilyCoordinator stage"
```

---

## Task 4: Implement Specialist Stage

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py`

**Step 1: Add _run_specialist method**

```python
async def _run_specialist(self, signal: dict, coordinator_result: dict) -> Optional[dict]:
    """Stage 3: Specialist validates signal technically.

    Specialist focuses ONLY on technical validation:
    - Is this actually a vulnerability?
    - Can it be exploited?
    - What's the technical evidence?

    Specialist does NOT consider threat model or business context.

    Args:
        signal: Signal dict from hunter
        coordinator_result: Output from FamilyCoordinator with specialist assignment

    Returns:
        Dict with verdict (vulnerable/not_vulnerable/needs_more_info), or None on error
    """
    from agents.deep_audit.subagents import get_specialist_prompt

    specialist_id = coordinator_result.get("primary_specialist", "generic_auditor")
    context = coordinator_result.get("context_for_specialist", "")

    # Get specialist info
    registry = SpecialistRegistry()
    specialist_info = registry.get_by_id(specialist_id)

    if not specialist_info:
        # Fallback to first specialist in family
        family_str = coordinator_result.get("family", "api_design")
        try:
            family = SpecialistFamily(family_str)
            family_specialists = registry.get_by_family(family)
            if family_specialists:
                specialist_info = family_specialists[0]
        except (ValueError, KeyError):
            pass

    if not specialist_info:
        print(f"[Overseer] No specialist found for {specialist_id}")
        return {"verdict": "needs_more_info", "error": "No specialist found"}

    # Format signal for specialist
    signal_context = f"""## Signal
- ID: {signal.get('signal_id', 'unknown')}
- Category: {signal.get('category', signal.get('vulnerability_type', 'unknown'))}
- File: {signal.get('file_path', signal.get('location', 'unknown'))}
- Line: {signal.get('line_start', signal.get('line_number', '?'))}
- Code: {signal.get('code_snippet', 'N/A')}
- Why suspicious: {signal.get('why_suspicious', signal.get('description', 'N/A'))}

## Additional Context from Coordinator
{context}"""

    prompt = get_specialist_prompt(
        specialist_name=specialist_info.name,
        specialist_id=specialist_info.id,
        proficiency=specialist_info.proficiency,
        signal_id=signal.get('signal_id', 'unknown'),
        signal_context=signal_context,
    )

    try:
        result = await self.dispatcher.dispatch_single_agent(
            agent_type="Specialist",
            objective=prompt,  # Full prompt as objective
            scope=self.repo_path_str,
            deliverable=f"/memories/verification/{specialist_id}_{signal.get('signal_id', 'unknown')}.json",
            time_budget=180,  # 3 minutes for thorough analysis
        )

        if result and result.output:
            verdict = self._extract_json_from_output(result.output)
            if verdict:
                verdict["specialist_id"] = specialist_id
                verdict["specialist_name"] = specialist_info.name
            return verdict
        return None

    except Exception as e:
        print(f"[Overseer] Specialist {specialist_id} failed: {e}")
        # Return error state - Triager will handle
        return {
            "verdict": "error",
            "specialist_id": specialist_id,
            "error": str(e),
        }
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(deep_audit): implement Specialist stage"
```

---

## Task 5: Implement Triager Stage

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py`

**Step 1: Add _run_triager method**

```python
async def _run_triager(self, signal: dict, specialist_result: Optional[dict]) -> Optional[dict]:
    """Stage 4: Triager classifies signal based on threat model.

    Triager makes final classification:
    - SECURITY_VULNERABILITY: Real, exploitable vuln matching threat model
    - HARDENING: Real issue but not in threat model scope (nice-to-fix)
    - BY_DESIGN: Intentional behavior, not a vulnerability
    - DISMISSED: Not a real vulnerability

    Triager considers:
    - Specialist's technical verdict (if available)
    - Threat model (what attackers are in scope)
    - Business context (what's actually at risk)

    Args:
        signal: Signal dict from hunter
        specialist_result: Output from Specialist (may be None or have error)

    Returns:
        Finding dict if classified as vulnerability, None if dismissed
    """
    from agents.deep_audit.subagents import get_triager_prompt

    # Get threat model from foundation context
    threat_model = "Unknown - no threat model available"
    try:
        tm_content = self.filesystem.read_file("/memories/foundation/threat_model.json")
        if tm_content:
            tm_data = self._extract_json_from_output(tm_content)
            if tm_data:
                threat_model = json.dumps(tm_data, indent=2)
    except Exception:
        pass

    # Format specialist verdict
    if specialist_result:
        if specialist_result.get("error"):
            specialist_summary = f"Specialist encountered error: {specialist_result.get('error')}"
        else:
            verdict = specialist_result.get("verdict", "unknown")
            confidence = specialist_result.get("confidence", "N/A")
            reasoning = specialist_result.get("reasoning", "No reasoning provided")
            specialist_summary = f"""Verdict: {verdict}
Confidence: {confidence}
Reasoning: {reasoning}"""
    else:
        specialist_summary = "No specialist verdict available (specialist failed or timed out)"

    signal_context = json.dumps(signal, indent=2)

    objective = f"""Make final classification for this signal.

## Signal
```json
{signal_context}
```

## Specialist Analysis
{specialist_summary}

## Threat Model
```json
{threat_model}
```

Classify as:
- SECURITY_VULNERABILITY: Real vuln, attacker in scope can exploit
- HARDENING: Real issue but attacker not in scope (nice-to-fix)
- BY_DESIGN: Intentional behavior
- DISMISSED: Not a real vulnerability

Output as JSON with: classification, severity, title, description, recommendation"""

    try:
        result = await self.dispatcher.dispatch_single_agent(
            agent_type="Triager",
            objective=objective,
            scope=self.repo_path_str,
            deliverable=f"/memories/triage/{signal.get('signal_id', 'unknown')}_triage.json",
            time_budget=120,  # 2 minutes
        )

        if result and result.output:
            triage_result = self._extract_json_from_output(result.output)
            if triage_result:
                classification = triage_result.get("classification", "DISMISSED")

                if classification == "SECURITY_VULNERABILITY":
                    # Build finding from triage result
                    return {
                        "signal_id": signal.get("signal_id"),
                        "title": triage_result.get("title", signal.get("title", "Untitled")),
                        "description": triage_result.get("description", ""),
                        "severity": triage_result.get("severity", "MEDIUM"),
                        "vulnerability_type": signal.get("category", signal.get("vulnerability_type", "unknown")),
                        "location": signal.get("file_path", signal.get("location", "")),
                        "file_path": signal.get("file_path", ""),
                        "line_start": signal.get("line_start", signal.get("line_number")),
                        "code_snippet": signal.get("code_snippet", ""),
                        "remediation": triage_result.get("recommendation", ""),
                        "confidence": specialist_result.get("confidence", 0.7) if specialist_result else 0.5,
                        "verified_by": specialist_result.get("specialist_id") if specialist_result else None,
                        "classification": classification,
                    }
                elif classification == "HARDENING":
                    # Still return as finding but lower priority
                    return {
                        "signal_id": signal.get("signal_id"),
                        "title": f"[Hardening] {triage_result.get('title', signal.get('title', 'Untitled'))}",
                        "description": triage_result.get("description", ""),
                        "severity": "LOW",  # Hardening items are always low
                        "vulnerability_type": signal.get("category", "hardening"),
                        "location": signal.get("file_path", ""),
                        "file_path": signal.get("file_path", ""),
                        "line_start": signal.get("line_start"),
                        "code_snippet": signal.get("code_snippet", ""),
                        "remediation": triage_result.get("recommendation", ""),
                        "confidence": 0.5,
                        "classification": classification,
                    }
                # BY_DESIGN and DISMISSED return None
                return None
        return None

    except Exception as e:
        print(f"[Overseer] Triager failed: {e}")
        return None
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(deep_audit): implement Triager stage with threat model classification"
```

---

## Task 6: Add dispatch_single_agent to Dispatcher

**Files:**
- Modify: `backend/agents/deep_audit/dispatcher.py`

**Step 1: Check if method exists, if not add it**

The routing methods use `dispatch_single_agent` which may not exist. Add this method to `WaveDispatcher` class:

```python
async def dispatch_single_agent(
    self,
    agent_type: str,
    objective: str,
    scope: str,
    deliverable: str,
    time_budget: int = 300,
) -> Optional[DispatchResult]:
    """Dispatch a single agent and wait for completion.

    This is a convenience wrapper for routing stages that need
    to wait for one agent's result before proceeding.

    Args:
        agent_type: Type of agent (Decider, FamilyCoordinator, Specialist, Triager)
        objective: What the agent should do
        scope: Path scope for the agent
        deliverable: Where to write output
        time_budget: Max seconds for this agent

    Returns:
        DispatchResult with output, or None on failure
    """
    task = DispatchTask(
        agent_type=agent_type,
        objective=objective,
        scope=scope,
        deliverable=deliverable,
        time_budget=time_budget,
    )

    wave = WavePlan(
        wave_id=0,  # Single dispatch, wave ID doesn't matter
        tasks=[task],
        rationale=f"Single dispatch: {agent_type}",
    )

    result = await self.dispatch_wave(wave)

    if result.results:
        return result.results[0]
    return None
```

**Step 2: Commit**

```bash
git add backend/agents/deep_audit/dispatcher.py
git commit -m "feat(deep_audit): add dispatch_single_agent for routing stages"
```

---

## Task 7: Wire Up Routing in Phase 4

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py`

**Step 1: Replace _dispatch_specialists with routing pipeline**

Modify the Phase 4 section in `analyze()` (around line 815-820) to use the new routing:

```python
# === PHASE 4: SIGNAL ROUTING ===
# Route each signal through: Decider → FamilyCoordinator → Specialist → Triager
if self.campaign_state.confirmed_findings and self.campaign_state.time_remaining() > 60:
    await self._route_all_signals()
```

**Step 2: Add _route_all_signals method**

```python
async def _route_all_signals(self):
    """Route all collected signals through the verification pipeline.

    Each signal goes through:
    1. Decider - Should we investigate?
    2. FamilyCoordinator - Which specialist? What context?
    3. Specialist - Is this technically a vulnerability?
    4. Triager - Final classification based on threat model
    """
    signals = self.campaign_state.confirmed_findings.copy()  # Copy since we'll modify
    self.campaign_state.confirmed_findings = []  # Clear, will re-add verified ones

    await self.emit_log(f"Phase 4: Routing {len(signals)} signals through verification pipeline...")
    print(f"[Overseer] Routing {len(signals)} signals through Decider → FamilyCoordinator → Specialist → Triager")

    # Create flow node for routing phase
    routing_node = flow_service.add_node(
        self.id,
        node_type="analysis",
        label="Signal Routing",
        parent_id=None,
        data={"phase": "routing", "signals_count": len(signals)},
    )
    if routing_node:
        flow_service.update_node_status(self.id, routing_node.id, "running")
    await self.emit_flow_update()

    verified_findings = []
    dismissed_count = 0
    error_count = 0

    for i, signal in enumerate(signals):
        # Check time budget
        if self.campaign_state.time_remaining() < 30:
            await self.emit_log(f"Time budget low, stopping routing at signal {i+1}/{len(signals)}")
            break

        signal_id = signal.get("signal_id", f"sig-{i}")
        await self.emit_log(f"Routing signal {i+1}/{len(signals)}: {signal_id}")

        try:
            finding = await self._route_signal_through_pipeline(signal)
            if finding:
                verified_findings.append(finding)
                await self.emit_log(f"  → Verified: {finding.get('title', 'Untitled')}")
            else:
                dismissed_count += 1
                await self.emit_log(f"  → Dismissed")
        except Exception as e:
            error_count += 1
            print(f"[Overseer] Error routing signal {signal_id}: {e}")
            await self.emit_log(f"  → Error: {e}")

    # Update confirmed findings with verified ones
    self.campaign_state.confirmed_findings = verified_findings

    if routing_node:
        flow_service.update_node_status(self.id, routing_node.id, "completed")
    await self.emit_flow_update()

    await self.emit_log(f"Routing complete: {len(verified_findings)} verified, {dismissed_count} dismissed, {error_count} errors")
    print(f"[Overseer] Routing complete: {len(verified_findings)} verified, {dismissed_count} dismissed, {error_count} errors")
```

**Step 3: Remove old _dispatch_specialists call**

In the `analyze()` method around line 815-820, change:

```python
# OLD:
if self.campaign_state.confirmed_findings and self.campaign_state.time_remaining() > 60:
    await self._dispatch_specialists()

# NEW:
if self.campaign_state.confirmed_findings and self.campaign_state.time_remaining() > 60:
    await self._route_all_signals()
```

**Step 4: Commit**

```bash
git add backend/agents/deep_audit/overseer.py
git commit -m "feat(deep_audit): wire up signal routing pipeline in Phase 4"
```

---

## Task 8: Test the Implementation

**Files:**
- None (testing)

**Step 1: Run a quick scan to verify routing works**

```bash
cd /Users/0xkato/gt/quick_hacker/mayor/rig
# Start backend if not running
# Run a quick scan on a test repo
```

**Step 2: Verify logs show routing stages**

Look for log output like:
- "Routing signal 1/N: sig-001"
- "Decider: investigate/dismiss"
- "FamilyCoordinator: assigned sql_injection_auditor"
- "Specialist: vulnerable/not_vulnerable"
- "Triager: SECURITY_VULNERABILITY/HARDENING/DISMISSED"

**Step 3: Close the bead**

```bash
bd close qh-c77 --reason "Implemented signal routing pipeline"
```

---

## Summary

This plan implements the full routing flow:

1. **Decider** - Evaluates each signal individually, decides investigate/dismiss
2. **FamilyCoordinator** - Picks specialist, provides CODE context (not threat model)
3. **Specialist** - Technical validation only
4. **Triager** - Final classification using threat model

Key design decisions:
- Each signal processed individually (not batched)
- FamilyCoordinator provides code context, NOT threat model
- Specialist errors don't drop signals - Triager still runs
- Triager uses threat model for SECURITY_VULNERABILITY vs HARDENING vs BY_DESIGN
