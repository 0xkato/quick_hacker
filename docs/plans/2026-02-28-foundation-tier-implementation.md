# Foundation Tier Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement #11 (Unknown State Promotion), #4 (Guard Effectiveness Rigor), and #10 (Evaluation Discipline) from `docs/plans/2026-02-28-pipeline-improvements-design.md`.

**Architecture:** Three targeted changes to the deep audit pipeline's data layer and reporting. #11 changes the default guard effectiveness from `"effective"` to `"unknown"` and updates scoring to deny unknown guards protective credit. #4 adds structural validation that auto-downgrades guards lacking evidence. #10 extends `SignalFlowTracker` to report unknown burden, guard evidence rate, and dismissed-with-unknowns metrics.

**Tech Stack:** Python 3.12, pytest, dataclasses (foundation.py), Counter-based tracking (signal_flow_tracker.py)

---

## Task 1: #11 — Add "unknown" to GuardInfo Effectiveness

**Files:**
- Modify: `backend/agents/deep_audit/foundation.py:705-738`
- Test: `backend/tests/agents/deep_audit/test_foundation.py`

### Step 1: Write the failing tests

Add tests to `test_foundation.py` that verify:
1. `GuardInfo.from_dict({})` defaults effectiveness to `"unknown"` (not `"effective"`)
2. `GuardInfo.from_dict({"effectiveness": "effective"})` preserves explicit `"effective"`
3. `GuardInfo.from_dict({"effectiveness": "unknown"})` accepts `"unknown"`
4. The `effectiveness` docstring includes `"unknown"` as a valid value

```python
class TestGuardInfo:
    def test_from_dict_defaults_effectiveness_to_unknown(self):
        """GuardInfo.from_dict() must default effectiveness to 'unknown', not 'effective'."""
        guard = GuardInfo.from_dict({})
        assert guard.effectiveness == "unknown"

    def test_from_dict_preserves_explicit_effective(self):
        """GuardInfo.from_dict() preserves 'effective' when explicitly provided."""
        guard = GuardInfo.from_dict({"effectiveness": "effective"})
        assert guard.effectiveness == "effective"

    def test_from_dict_accepts_unknown_effectiveness(self):
        """GuardInfo.from_dict() accepts 'unknown' as a valid effectiveness value."""
        guard = GuardInfo.from_dict({"effectiveness": "unknown"})
        assert guard.effectiveness == "unknown"

    def test_from_dict_roundtrip(self):
        """GuardInfo.to_dict() -> from_dict() preserves all fields."""
        original = GuardInfo(
            file_path="src/auth.py",
            line_number=42,
            guard_type="authorization",
            code_snippet="if user.is_admin:",
            description="Admin check",
            effectiveness="partial",
            bypass_reason="Only checks role, not resource ownership",
        )
        restored = GuardInfo.from_dict(original.to_dict())
        assert restored.file_path == original.file_path
        assert restored.effectiveness == "partial"
        assert restored.bypass_reason == "Only checks role, not resource ownership"
```

**Import needed:** Add `GuardInfo` to the existing import line at `test_foundation.py:3`:
```python
from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
    TrustBoundary,
    AttackerCapability,
    SuspiciousSignal,
    SignalCategory,
    SignalSeverity,
    GuardInfo,  # NEW
)
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py::TestGuardInfo -v`
Expected: `test_from_dict_defaults_effectiveness_to_unknown` FAILS because `GuardInfo.from_dict({})` currently returns `effectiveness="effective"`

### Step 3: Fix GuardInfo.from_dict() default and docstring

In `backend/agents/deep_audit/foundation.py`:

**Line 713** — Update the effectiveness docstring:
```python
    effectiveness: str       # "effective" | "partial" | "bypassable" | "unknown"
```

**Line 735** — Change the default:
```python
            effectiveness=data.get("effectiveness", "unknown"),
```

### Step 4: Run tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py -v`
Expected: All tests PASS (including all existing tests)

### Step 5: Commit

```bash
git add backend/agents/deep_audit/foundation.py backend/tests/agents/deep_audit/test_foundation.py
git commit -m "feat(deep-audit): default GuardInfo effectiveness to 'unknown'

Unknown never clears a path on its own. Guards without evaluated
effectiveness now default to 'unknown' instead of 'effective'.
Implements #11 from pipeline improvements design."
```

---

## Task 2: #11 — Update compute_trace_quality() Guard Scoring

**Files:**
- Modify: `backend/agents/deep_audit/foundation.py:499-534`
- Test: `backend/tests/agents/deep_audit/test_foundation.py`

### Step 1: Write the failing tests

Add tests to `test_foundation.py` that verify guard scoring respects effectiveness:

```python
class TestComputeTraceQuality:
    def _make_signal(self, trace_steps=None, guards=None):
        """Helper to build a SuspiciousSignal with specific trace data."""
        return SuspiciousSignal(
            signal_id="test-sig",
            category=SignalCategory.COMMAND_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="src/api/run.py",
            line_start=10,
            code_snippet="os.system(cmd)",
            why_suspicious="User input in command",
            entry_point_trace=["POST /run"],
            trace_steps=trace_steps or [],
            guards=guards or [],
        )

    def test_unknown_guards_get_no_credit(self):
        """Guards with 'unknown' effectiveness contribute 0 to trace quality."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "unknown"},
            ],
        )
        quality = signal.compute_trace_quality()
        # source=0.3, sink=0.3, steps=0.2*(2/2)=0.2, guards=0 (unknown), steps>=3=0 → 0.8
        # But only 2 steps, so no +0.1 for >=3. Total: 0.3+0.3+0.2=0.8
        assert quality == pytest.approx(0.8)

    def test_effective_guards_get_credit(self):
        """Guards with 'effective' effectiveness get the +0.1 credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "effective"},
            ],
        )
        quality = signal.compute_trace_quality()
        # source=0.3, sink=0.3, steps=0.2, guards=0.1 (effective with snippet) → 0.9
        assert quality == pytest.approx(0.9)

    def test_partial_guards_get_credit(self):
        """Guards with 'partial' effectiveness get credit (they were evaluated)."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "partial"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.9)

    def test_bypassable_guards_get_credit(self):
        """Guards with 'bypassable' effectiveness get credit (they were evaluated)."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "bypassable", "bypass_reason": "encoding bypass"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.9)

    def test_no_guards_no_guard_credit(self):
        """Signals with no guards get 0 guard credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[],
        )
        quality = signal.compute_trace_quality()
        # source=0.3, sink=0.3, steps=0.2, guards=0, steps>=3=0 → 0.8
        assert quality == pytest.approx(0.8)

    def test_guard_without_snippet_gets_no_credit(self):
        """Guards without code_snippet get no credit, even if marked effective."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "", "effectiveness": "effective"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.8)

    def test_mixed_guards_only_evaluated_get_credit(self):
        """Only guards with evaluated (non-unknown) effectiveness AND code snippets get credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "propagation", "file_path": "a.py", "line_number": 5},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "check(x)", "effectiveness": "unknown"},
                {"code_snippet": "sanitize(x)", "effectiveness": "effective"},
            ],
        )
        quality = signal.compute_trace_quality()
        # source=0.3, sink=0.3, steps=0.2*(3/3)=0.2, guards=0.1 (one effective with snippet), steps>=3=0.1 → 1.0
        assert quality == pytest.approx(1.0)
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py::TestComputeTraceQuality -v`
Expected: `test_unknown_guards_get_no_credit` FAILS because the current code awards +0.1 for any guard with a code_snippet, regardless of effectiveness

### Step 3: Update compute_trace_quality() guard scoring

In `backend/agents/deep_audit/foundation.py`, replace lines 526-528:

**Old code (lines 526-528):**
```python
        # Only count guards with actual code evidence (not placeholders from unstructured guards_present)
        if self.guards and any(g.get("code_snippet") for g in self.guards):
            score += 0.1
```

**New code:**
```python
        # Only count guards with code evidence AND evaluated effectiveness (not unknown/defaulted)
        if self.guards and any(
            g.get("code_snippet") and g.get("effectiveness", "unknown") != "unknown"
            for g in self.guards
        ):
            score += 0.1
```

### Step 4: Run tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py -v`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/agents/deep_audit/foundation.py backend/tests/agents/deep_audit/test_foundation.py
git commit -m "feat(deep-audit): unknown guards receive no protective credit in trace quality

compute_trace_quality() now requires guards to have both code_snippet
AND evaluated effectiveness (not 'unknown') to receive the +0.1 credit.
Implements #11 guard scoring from pipeline improvements design."
```

---

## Task 3: #11 — Update Overseer Pre-Screen for Unknown Guards

**Files:**
- Modify: `backend/agents/deep_audit/overseer.py:1622-1627`
- Test: `backend/tests/agents/deep_audit/test_foundation.py` (pre-screen is integration, verify via manual check)

### Step 1: Review the pre-screen logic

The pre-screen at `overseer.py:1622-1627` adjusts confidence based on guard effectiveness:
```python
structured_guards = signal.get("guards", [])
if structured_guards:
    effective_guards = [g for g in structured_guards if isinstance(g, dict) and g.get("effectiveness") == "effective"]
    if effective_guards:
        confidence_adjustment -= 0.15 * min(len(effective_guards), 2)
```

This is already correct — it only adjusts confidence for `"effective"` guards, not `"unknown"`. No change needed to this code since:
- `"unknown"` guards won't match `g.get("effectiveness") == "effective"`
- The pre-screen already ignores non-effective guards

**Decision: No change needed.** The pre-screen already handles `"unknown"` correctly by not giving it credit.

### Step 2: Verify the unstructured-to-structured guard conversion

At `overseer.py:1437-1451`, unstructured `guards_present` strings are converted to structured guards with `"effectiveness": "unknown"`. This is already correct — it was already defaulting to `"unknown"` for these conversions. No change needed.

### Step 3: Commit (skip — no changes)

No changes were needed. The existing overseer code already handles unknown guards correctly in pre-screen and guard conversion.

---

## Task 4: #4 — Add validate_guard_effectiveness() Method to GuardInfo

**Files:**
- Modify: `backend/agents/deep_audit/foundation.py:705-738`
- Test: `backend/tests/agents/deep_audit/test_foundation.py`

### Step 1: Write the failing tests

Add tests to the existing `TestGuardInfo` class:

```python
    def test_validate_downgrades_effective_without_snippet(self):
        """A guard marked 'effective' without code_snippet is downgraded to 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="",
            description="Validates input",
            effectiveness="effective",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"

    def test_validate_downgrades_effective_without_bypass_resistance(self):
        """A guard marked 'effective' without bypass_reason explanation is downgraded to 'unknown'.

        The design requires effective guards to explain why bypass is not feasible.
        We repurpose bypass_reason as the field for this: for effective guards,
        bypass_reason contains why bypass is NOT feasible. For bypassable guards,
        it contains the bypass method.
        """
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="if not re.match(r'^[a-z]+$', user_input):",
            description="Validates input is lowercase alpha",
            effectiveness="effective",
            bypass_reason="",  # No explanation of why bypass fails
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"

    def test_validate_keeps_effective_with_full_evidence(self):
        """A guard with code_snippet AND bypass_reason stays 'effective'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="if not re.match(r'^[a-z]+$', user_input): raise ValueError",
            description="Validates input is lowercase alpha only",
            effectiveness="effective",
            bypass_reason="Regex is anchored and restrictive; no bypass feasible",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "effective"

    def test_validate_keeps_partial_with_snippet(self):
        """A guard marked 'partial' with code_snippet stays 'partial'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="sanitization",
            code_snippet="html.escape(user_input)",
            description="HTML escapes user input",
            effectiveness="partial",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "partial"

    def test_validate_downgrades_partial_without_snippet(self):
        """A guard marked 'partial' without code_snippet is downgraded to 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="sanitization",
            code_snippet="",
            description="Sanitizes input",
            effectiveness="partial",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"

    def test_validate_keeps_bypassable(self):
        """A guard marked 'bypassable' stays 'bypassable' (already weakest evaluated state)."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="",
            description="Validates input",
            effectiveness="bypassable",
            bypass_reason="Encoding bypass allows special chars",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "bypassable"

    def test_validate_keeps_unknown(self):
        """A guard already 'unknown' stays 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="",
            description="Validates input",
            effectiveness="unknown",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py::TestGuardInfo::test_validate_downgrades_effective_without_snippet -v`
Expected: FAILS with `AttributeError: 'GuardInfo' object has no attribute 'validate_effectiveness'`

### Step 3: Add validate_effectiveness() to GuardInfo

In `backend/agents/deep_audit/foundation.py`, add method to `GuardInfo` class after `from_dict()` (after line 737):

```python
    def validate_effectiveness(self) -> None:
        """System-enforced guard validation. Downgrades unsupported claims.

        Rules:
        - A guard without code_snippet is automatically 'unknown' (regardless of LLM claim)
        - A guard marked 'effective' without bypass_reason is downgraded to 'unknown'
        - 'partial' requires code_snippet
        - 'bypassable' and 'unknown' are not downgraded (already weak/honest)
        """
        if self.effectiveness in ("bypassable", "unknown"):
            return

        if not self.code_snippet or not self.code_snippet.strip():
            self.effectiveness = "unknown"
            return

        if self.effectiveness == "effective" and (not self.bypass_reason or not self.bypass_reason.strip()):
            self.effectiveness = "unknown"
```

### Step 4: Run tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py::TestGuardInfo -v`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/agents/deep_audit/foundation.py backend/tests/agents/deep_audit/test_foundation.py
git commit -m "feat(deep-audit): add validate_effectiveness() to GuardInfo

System-enforced structural validation: guards marked 'effective' without
code_snippet or bypass resistance explanation are downgraded to 'unknown'.
LLM proposes, system enforces. Implements #4 from pipeline improvements design."
```

---

## Task 5: #4 — Wire validate_effectiveness() Into Pipeline

**Files:**
- Modify: `backend/agents/deep_audit/foundation.py:499-534` (compute_trace_quality)
- Modify: `backend/agents/deep_audit/overseer.py:1434` (signal parsing)
- Modify: `backend/agents/deep_audit/overseer.py:2065` (DataflowTracer output)
- Test: `backend/tests/agents/deep_audit/test_foundation.py`

### Step 1: Write a failing integration test

Add to `TestComputeTraceQuality`:

```python
    def test_compute_trace_quality_validates_guards(self):
        """compute_trace_quality() runs validate_effectiveness() on guards before scoring.

        A guard marked 'effective' by the LLM but without bypass_reason
        should be auto-downgraded to 'unknown' and get no credit.
        """
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {
                    "code_snippet": "sanitize(x)",
                    "effectiveness": "effective",
                    # Missing bypass_reason → will be downgraded to unknown
                },
            ],
        )
        quality = signal.compute_trace_quality()
        # Guard gets downgraded to unknown → no credit → 0.3+0.3+0.2 = 0.8
        assert quality == pytest.approx(0.8)
        # Verify the guard was actually downgraded
        assert signal.guards[0]["effectiveness"] == "unknown"
```

### Step 2: Run test to verify it fails

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py::TestComputeTraceQuality::test_compute_trace_quality_validates_guards -v`
Expected: FAILS because `compute_trace_quality()` doesn't call `validate_effectiveness()` yet, so the guard stays `"effective"` and gets credit (0.9, not 0.8)

### Step 3: Wire validation into compute_trace_quality()

In `backend/agents/deep_audit/foundation.py`, modify `compute_trace_quality()`. Insert validation before the guard scoring block (before the current line 526):

**Add before the guard scoring section:**
```python
        # Validate guard effectiveness claims (system-enforced)
        for g in self.guards:
            guard = GuardInfo.from_dict(g)
            guard.validate_effectiveness()
            g["effectiveness"] = guard.effectiveness
```

The full guard section becomes:
```python
        # Validate guard effectiveness claims (system-enforced)
        for g in self.guards:
            guard = GuardInfo.from_dict(g)
            guard.validate_effectiveness()
            g["effectiveness"] = guard.effectiveness

        # Only count guards with code evidence AND evaluated effectiveness (not unknown/defaulted)
        if self.guards and any(
            g.get("code_snippet") and g.get("effectiveness", "unknown") != "unknown"
            for g in self.guards
        ):
            score += 0.1
```

### Step 4: Run all tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_foundation.py -v`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/agents/deep_audit/foundation.py backend/tests/agents/deep_audit/test_foundation.py
git commit -m "feat(deep-audit): wire guard validation into compute_trace_quality()

Guards are now validated before scoring: LLM claims without evidence
are downgraded to 'unknown' before the score is computed.
Implements #4 pipeline wiring from pipeline improvements design."
```

---

## Task 6: #10 — Add signal_source to SignalTrace

**Files:**
- Modify: `backend/agents/deep_audit/signal_flow_tracker.py:12-24`
- Modify: `backend/agents/deep_audit/signal_flow_tracker.py:48-54`
- Test: `backend/tests/agents/deep_audit/test_signal_flow_tracker.py`

### Step 1: Write the failing tests

Add to `test_signal_flow_tracker.py`:

```python
class TestSignalSource:
    def test_signal_trace_has_signal_source_field(self):
        """SignalTrace has a signal_source field defaulting to 'sink_hunter'."""
        trace = SignalTrace(signal_id="sig-1", title="Test", severity="HIGH")
        assert trace.signal_source == "sink_hunter"

    def test_enter_accepts_signal_source(self):
        """SignalFlowTracker.enter() accepts optional signal_source parameter."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH", signal_source="behavioral_sink")
        assert tracker.traces["sig-1"].signal_source == "behavioral_sink"

    def test_enter_defaults_signal_source(self):
        """SignalFlowTracker.enter() defaults signal_source to 'sink_hunter'."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        assert tracker.traces["sig-1"].signal_source == "sink_hunter"

    def test_summary_includes_by_signal_source(self):
        """summary() includes by_signal_source counts."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SQL Injection", "HIGH", signal_source="sink_hunter")
        tracker.enter("sig-2", "Missing auth", "HIGH", signal_source="policy_deviation")
        tracker.enter("sig-3", "IDOR", "MEDIUM", signal_source="behavioral_sink")

        s = tracker.summary()
        assert "by_signal_source" in s
        assert s["by_signal_source"]["sink_hunter"] == 1
        assert s["by_signal_source"]["policy_deviation"] == 1
        assert s["by_signal_source"]["behavioral_sink"] == 1
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py::TestSignalSource -v`
Expected: FAILS — `SignalTrace` has no `signal_source` field, `enter()` doesn't accept it

### Step 3: Add signal_source to SignalTrace and SignalFlowTracker

In `backend/agents/deep_audit/signal_flow_tracker.py`:

**Modify `SignalTrace` dataclass (lines 12-23)** — add field:
```python
@dataclass
class SignalTrace:
    """Tracks a single signal's journey through the pipeline."""

    signal_id: str
    title: str
    severity: str
    stages: list[dict] = field(default_factory=list)
    final_disposition: str = "unknown"  # persisted, dismissed, unverified, error, deduped
    classification: Optional[str] = None
    drop_stage: Optional[str] = None
    drop_reason: Optional[str] = None
    signal_source: str = "sink_hunter"  # sink_hunter, behavioral_sink, entrypoint_hunter, policy_deviation, error_path, boundary_crossing, config_conditional, pattern_match
```

**Modify `enter()` method (lines 48-54)** — accept signal_source:
```python
    def enter(self, signal_id: str, title: str, severity: str, signal_source: str = "sink_hunter"):
        """Signal enters the routing pipeline."""
        self.traces[signal_id] = SignalTrace(
            signal_id=signal_id,
            title=title[:80],
            severity=severity,
            signal_source=signal_source,
        )
```

**Modify `summary()` method (lines 86-136)** — add by_signal_source:

After the `by_classification` Counter (line 93-95), add:
```python
        by_signal_source = Counter(t.signal_source for t in self.traces.values())
```

And in the return dict (after `"by_classification"` on line 131), add:
```python
            "by_signal_source": dict(by_signal_source),
```

### Step 4: Run tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py -v`
Expected: All tests PASS (including all existing tests — `enter()` signature is backward-compatible)

### Step 5: Commit

```bash
git add backend/agents/deep_audit/signal_flow_tracker.py backend/tests/agents/deep_audit/test_signal_flow_tracker.py
git commit -m "feat(deep-audit): add signal_source tracking to SignalFlowTracker

Every signal entering the pipeline now carries a signal_source tag
(sink_hunter, behavioral_sink, policy_deviation, etc). Summary reports
per-source signal yield. Implements #10 provenance tracking."
```

---

## Task 7: #10 — Add dismissed_with_unknowns Tracking

**Files:**
- Modify: `backend/agents/deep_audit/signal_flow_tracker.py`
- Test: `backend/tests/agents/deep_audit/test_signal_flow_tracker.py`

### Step 1: Write the failing tests

Add to `test_signal_flow_tracker.py`:

```python
class TestDismissedWithUnknowns:
    def test_record_drop_with_unknowns_flag(self):
        """record_drop() accepts has_unknowns flag to track dismissed-with-unknowns."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        tracker.record_drop("sig-1", "triager", "dismissed/by_design", has_unknowns=True)
        trace = tracker.traces["sig-1"]
        assert trace.has_unknowns is True

    def test_record_drop_defaults_no_unknowns(self):
        """record_drop() defaults has_unknowns to False."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        tracker.record_drop("sig-1", "triager", "dismissed/by_design")
        trace = tracker.traces["sig-1"]
        assert trace.has_unknowns is False

    def test_summary_includes_dismissed_with_unknowns_count(self):
        """summary() includes dismissed_with_unknowns count."""
        tracker = SignalFlowTracker()

        # Dismissed with unknowns
        tracker.enter("sig-1", "Guard unclear", "HIGH")
        tracker.record_drop("sig-1", "triager", "dismissed/by_design", has_unknowns=True)

        # Dismissed without unknowns
        tracker.enter("sig-2", "Not real", "LOW")
        tracker.record_drop("sig-2", "decider", "not in scope")

        # Verified (not dismissed)
        tracker.enter("sig-3", "Real vuln", "HIGH")
        tracker.record_stage("sig-3", "triager", "SECURITY_VULNERABILITY")

        s = tracker.summary()
        assert s["dismissed_with_unknowns"] == 1

    def test_dismissed_with_unknowns_in_warnings(self):
        """summary() warns when signals were dismissed despite unresolved unknowns."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Guard unclear", "HIGH")
        tracker.record_drop("sig-1", "triager", "dismissed/by_design", has_unknowns=True)

        s = tracker.summary()
        assert any("dismissed with unresolved unknowns" in w for w in s["warnings"])
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py::TestDismissedWithUnknowns -v`
Expected: FAILS — `record_drop()` doesn't accept `has_unknowns`, `SignalTrace` has no `has_unknowns` field

### Step 3: Implement dismissed-with-unknowns tracking

In `backend/agents/deep_audit/signal_flow_tracker.py`:

**Add `has_unknowns` to `SignalTrace`** (after `drop_reason` field):
```python
    has_unknowns: bool = False
```

**Update `record_drop()` to accept `has_unknowns`:**
```python
    def record_drop(self, signal_id: str, stage: str, reason: str, has_unknowns: bool = False):
        """Signal was dropped at this stage."""
        trace = self.traces.get(signal_id)
        if not trace:
            return
        trace.stages.append({"stage": stage, "result": "dropped", "detail": reason})
        trace.final_disposition = "dismissed"
        trace.drop_stage = stage
        trace.drop_reason = reason[:200] if reason else ""
        trace.has_unknowns = has_unknowns
```

**Update `summary()` to include `dismissed_with_unknowns`:**

After the `dropped_signals` list (around line 107), add:
```python
        dismissed_with_unknowns = sum(
            1 for t in self.traces.values()
            if t.final_disposition == "dismissed" and t.has_unknowns
        )
```

In the warnings list, add:
```python
        if dismissed_with_unknowns > 0:
            warnings.append(
                f"{dismissed_with_unknowns} signal(s) dismissed with unresolved unknowns"
            )
```

In the return dict, add:
```python
            "dismissed_with_unknowns": dismissed_with_unknowns,
```

### Step 4: Run all tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py -v`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/agents/deep_audit/signal_flow_tracker.py backend/tests/agents/deep_audit/test_signal_flow_tracker.py
git commit -m "feat(deep-audit): track dismissed-with-unknowns in SignalFlowTracker

Signals dismissed while carrying unresolved unknowns are now tracked
and surfaced in the health report as warnings. This makes uncertainty-based
dismissals visible and reviewable. Implements #11/#10 integration."
```

---

## Task 8: #10 — Add Guard Evidence Rate to Summary

**Files:**
- Modify: `backend/agents/deep_audit/signal_flow_tracker.py`
- Test: `backend/tests/agents/deep_audit/test_signal_flow_tracker.py`

### Step 1: Write the failing tests

Add to `test_signal_flow_tracker.py`:

```python
class TestGuardEvidenceRate:
    def test_record_guard_stats(self):
        """record_guard_stats() tracks guard evidence for evaluation."""
        tracker = SignalFlowTracker()
        tracker.record_guard_stats(total=5, with_evidence=3, unknown=2)
        s = tracker.summary()
        assert s["guard_stats"]["total_guards"] == 5
        assert s["guard_stats"]["with_evidence"] == 3
        assert s["guard_stats"]["unknown"] == 2
        assert s["guard_stats"]["evidence_rate"] == pytest.approx(0.6)

    def test_record_guard_stats_accumulates(self):
        """Multiple calls to record_guard_stats() accumulate."""
        tracker = SignalFlowTracker()
        tracker.record_guard_stats(total=3, with_evidence=2, unknown=1)
        tracker.record_guard_stats(total=2, with_evidence=0, unknown=2)
        s = tracker.summary()
        assert s["guard_stats"]["total_guards"] == 5
        assert s["guard_stats"]["with_evidence"] == 2
        assert s["guard_stats"]["unknown"] == 3
        assert s["guard_stats"]["evidence_rate"] == pytest.approx(0.4)

    def test_guard_stats_default_empty(self):
        """Guard stats default to zeros when no guards recorded."""
        tracker = SignalFlowTracker()
        s = tracker.summary()
        assert s["guard_stats"]["total_guards"] == 0
        assert s["guard_stats"]["evidence_rate"] == 0.0

    def test_low_evidence_rate_warning(self):
        """summary() warns when guard evidence rate is below 50%."""
        tracker = SignalFlowTracker()
        tracker.record_guard_stats(total=10, with_evidence=3, unknown=7)
        s = tracker.summary()
        assert any("guard evidence rate" in w.lower() for w in s["warnings"])
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py::TestGuardEvidenceRate -v`
Expected: FAILS — `record_guard_stats()` doesn't exist

### Step 3: Implement guard stats tracking

In `backend/agents/deep_audit/signal_flow_tracker.py`:

**Add counters to `__init__()` (after `self.persist_stats`):**
```python
        self.guard_total = 0
        self.guard_with_evidence = 0
        self.guard_unknown = 0
```

**Add `record_guard_stats()` method (after `record_persist()`):**
```python
    def record_guard_stats(self, total: int, with_evidence: int, unknown: int):
        """Track guard evidence metrics for evaluation record."""
        self.guard_total += total
        self.guard_with_evidence += with_evidence
        self.guard_unknown += unknown
```

**Update `summary()` to include guard stats:**

Add to the return dict:
```python
            "guard_stats": {
                "total_guards": self.guard_total,
                "with_evidence": self.guard_with_evidence,
                "unknown": self.guard_unknown,
                "evidence_rate": (
                    self.guard_with_evidence / self.guard_total
                    if self.guard_total > 0 else 0.0
                ),
            },
```

Add to warnings:
```python
        if self.guard_total > 0 and (self.guard_with_evidence / self.guard_total) < 0.5:
            warnings.append(
                f"Low guard evidence rate: {self.guard_with_evidence}/{self.guard_total} "
                f"({self.guard_with_evidence / self.guard_total:.0%}) guards have validated evidence"
            )
```

### Step 4: Run all tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py -v`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/agents/deep_audit/signal_flow_tracker.py backend/tests/agents/deep_audit/test_signal_flow_tracker.py
git commit -m "feat(deep-audit): add guard evidence rate to pipeline health report

SignalFlowTracker now tracks how many guards had validated evidence vs
defaulted to unknown. Low evidence rate (<50%) triggers a warning.
Implements #10 guard evidence metric from pipeline improvements design."
```

---

## Task 9: #10 — Update print_report() and summary_text() for New Metrics

**Files:**
- Modify: `backend/agents/deep_audit/signal_flow_tracker.py:138-243`
- Test: `backend/tests/agents/deep_audit/test_signal_flow_tracker.py`

### Step 1: Write the failing tests

Add to `test_signal_flow_tracker.py`:

```python
class TestExtendedReport:
    def test_summary_text_includes_signal_sources(self):
        """summary_text() mentions signal source distribution."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SQL Injection", "HIGH", signal_source="sink_hunter")
        tracker.enter("sig-2", "Missing auth", "HIGH", signal_source="policy_deviation")
        tracker.record_stage("sig-1", "triager", "SECURITY_VULNERABILITY")
        tracker.record_parse("json_ok")
        tracker.record_persist("saved")
        tracker.record_drop("sig-2", "specialist", "not exploitable")

        text = tracker.summary_text()
        assert "sources:" in text.lower() or "sink_hunter" in text

    def test_print_report_includes_guard_stats(self):
        """print_report() includes guard evidence section."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SQL Injection", "HIGH")
        tracker.record_stage("sig-1", "triager", "SECURITY_VULNERABILITY")
        tracker.record_parse("json_ok")
        tracker.record_persist("saved")
        tracker.record_guard_stats(total=4, with_evidence=3, unknown=1)

        captured = io.StringIO()
        sys.stdout = captured
        try:
            tracker.print_report()
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "Guard Evidence" in output
        assert "3/4" in output or "75%" in output

    def test_print_report_includes_dismissed_with_unknowns(self):
        """print_report() includes dismissed-with-unknowns section."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Unclear guard", "HIGH")
        tracker.record_drop("sig-1", "triager", "dismissed/by_design", has_unknowns=True)

        captured = io.StringIO()
        sys.stdout = captured
        try:
            tracker.print_report()
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "unknown" in output.lower()
```

### Step 2: Run tests to verify they fail

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py::TestExtendedReport -v`
Expected: FAILS — print_report() and summary_text() don't include the new metrics

### Step 3: Update summary_text() and print_report()

In `backend/agents/deep_audit/signal_flow_tracker.py`:

**Update `summary_text()` (currently lines 138-166):**

After the existing parts list assembly, before the return, add:
```python
        # Signal source distribution
        by_source = s.get("by_signal_source", {})
        if by_source and len(by_source) > 1:
            source_parts = [f"{v}x {k}" for k, v in sorted(by_source.items())]
            parts.append(f"sources: [{', '.join(source_parts)}]")

        # Unknown burden
        dwu = s.get("dismissed_with_unknowns", 0)
        if dwu > 0:
            parts.append(f"{dwu} dismissed-with-unknowns")
```

**Update `print_report()` (currently lines 168-242):**

After the Persistence section (after `lines.append(f"  |-- DB Error:        {persist.get('db_error', 0):>3}")`), add:

```python
        # Guard Evidence section
        guard = s.get("guard_stats", {})
        if guard.get("total_guards", 0) > 0:
            rate = guard["evidence_rate"]
            lines.append("  |")
            lines.append("  Guard Evidence:")
            lines.append(f"  |-- Total Guards:    {guard['total_guards']:>3}")
            lines.append(f"  |-- With Evidence:   {guard['with_evidence']:>3}")
            lines.append(f"  |-- Unknown:         {guard['unknown']:>3}")
            lines.append(f"  |-- Evidence Rate:   {rate:>5.0%}")

        # Dismissed with unknowns
        dwu = s.get("dismissed_with_unknowns", 0)
        if dwu > 0:
            lines.append("  |")
            lines.append(f"  Unknown Burden:      {dwu:>3} dismissed with unknowns")
```

### Step 4: Run all tests to verify they pass

Run: `python -m pytest backend/tests/agents/deep_audit/test_signal_flow_tracker.py -v`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/agents/deep_audit/signal_flow_tracker.py backend/tests/agents/deep_audit/test_signal_flow_tracker.py
git commit -m "feat(deep-audit): extend health report with guard evidence and unknown burden

print_report() and summary_text() now include guard evidence rate,
signal source distribution, and dismissed-with-unknowns metrics.
Completes #10 evaluation discipline from pipeline improvements design."
```

---

## Task 10: Run Full Test Suite and Verify

**Files:**
- All modified files from Tasks 1-9

### Step 1: Run the full test suite

Run: `python -m pytest backend/tests/ -x -q`
Expected: All tests PASS

### Step 2: Run only the deep audit tests with verbose output

Run: `python -m pytest backend/tests/agents/deep_audit/ -v`
Expected: All tests PASS, new tests visible in output

### Step 3: Verify no regressions in other tests

Run: `python -m pytest backend/tests/ -x -q --tb=short`
Expected: All tests PASS

### Step 4: Final commit (if any fixes needed)

If any tests failed, fix them and commit the fixes.

---

## Summary of Changes

| Task | Item | What Changed | Files |
|------|------|-------------|-------|
| 1 | #11 | GuardInfo default `"effective"` → `"unknown"` | foundation.py, test_foundation.py |
| 2 | #11 | compute_trace_quality() denies unknown guards credit | foundation.py, test_foundation.py |
| 3 | #11 | Verified overseer pre-screen already handles unknowns | (no changes needed) |
| 4 | #4 | validate_effectiveness() structural validation | foundation.py, test_foundation.py |
| 5 | #4 | Wire validation into compute_trace_quality() | foundation.py, test_foundation.py |
| 6 | #10 | signal_source tracking on SignalTrace | signal_flow_tracker.py, test_signal_flow_tracker.py |
| 7 | #11/#10 | dismissed_with_unknowns tracking | signal_flow_tracker.py, test_signal_flow_tracker.py |
| 8 | #10 | Guard evidence rate metric | signal_flow_tracker.py, test_signal_flow_tracker.py |
| 9 | #10 | print_report()/summary_text() extended output | signal_flow_tracker.py, test_signal_flow_tracker.py |
| 10 | All | Full test suite verification | (all) |
