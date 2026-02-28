# Deep Audit Pipeline Improvements Design

**Date:** 2026-02-28
**Version:** 1.1
**Status:** Draft

## Purpose

This document defines 11 behavioral corrections and capability expansions for the deep audit pipeline. Each item identifies a wrong assumption in the current system, the rule that replaces it, which pipeline decisions change, what mistakes are reduced, and how success is measured.

Items are grouped into tiers by dependency and implementation order.

---

## Glossary

Two terms are used throughout this document and must not be conflated:

- **Unknown** — the system evaluated something but cannot justify its effect. The analysis was attempted; the conclusion is "we don't know what this does." Unknown blocks unjustified dismissal: a guard with unknown effectiveness cannot be used to argue a path is safe.

- **Unverified** — the proof step itself has not been completed. The analysis was not attempted, or was attempted but did not finish. Unverified means the pipeline owes more work before strong conclusions in either direction.

The distinction matters because they imply different responses:

| State | Meaning | Pipeline response |
|-------|---------|-------------------|
| Unknown | Looked, can't justify | Cannot clear the path; flag for reviewer |
| Unverified | Didn't look yet | Cannot conclude either way; schedule more work if budget allows |

Both states share one rule: **neither clears a path on its own.**

---

## Evidence Layers

Several items in this design reference evidence that comes from different sources with different reliability. The system must distinguish three layers:

1. **Codebase evidence** — what the code structurally says. Route registrations, decorator presence, function calls, data flow. This is the most reliable layer because it comes from reading actual source files.

2. **Threat-model-dependent interpretation** — whether the observed behavior matters given the attacker model. A vulnerability behind an admin-only endpoint is real in the code, but only exploitable if the threat model includes authenticated attackers. This layer depends on `ThreatModelProfile.attacker_capabilities` (threat_model_profile.py:22-29) and the threat model preset (`A`, `AB`, `ABC`).

3. **Deployment-dependent interpretation** — whether the observed behavior is active in the target deployment. A debug endpoint exists in code, but may be disabled in production via environment variable. A feature-flag-gated code path is real, but may not be reachable in the deployed configuration.

The system should always be able to state:

- "This behavior exists in the code" (codebase evidence)
- "This attacker can / cannot reach it" (threat model interpretation)
- "This is / is not active in the assumed deployment" (deployment interpretation)

These layers are especially relevant to #1 (Expected Behavior), #3 (Preconditions), #5 (Expanded Sources), and #7 (Reachability). A finding should never be dismissed by collapsing these layers — "this is debug-only" is a deployment claim, not a codebase claim, and requires deployment evidence.

---

## Non-Goals

These are not goals of this design. Each is a common misreading of the proposals:

- **Unknown does not automatically mean vulnerable.** Unknown means not established. It blocks dismissal, but it does not create a finding.
- **The intent map does not automatically mean safe.** Inferred intent is a reference, not an authority. It supports classification but does not override evidence.
- **Pattern match does not auto-confirm sibling findings.** A confirmed pattern creates a high-priority signal. That signal still goes through the full pipeline.
- **Reachability does not erase real issues without evidence.** Unreachability must be established, not assumed. `debug_test_only` classification requires proof that the code is actually gated.
- **New signal sources do not lower the proof bar.** Every signal — from deviation detection, error-path hunting, pattern matching, or behavioral sink analysis — goes through the same DataflowTracer → Specialist → Devil's Advocate → Triager pipeline.
- **The evaluation record does not prove objective security ground truth.** It measures pipeline behavior, consistency, productivity, and regression. Ground-truth validation still comes from benchmarked cases, known findings, or manual review.

---

## Current System Reference

### Pipeline Stages (7-stage routing)

```
Pre-screen → Decider → DataflowTracer → FamilyCoordinator → Specialist → Devil's Advocate → Triager
```

### Key Data Structures

| Structure | Location | Purpose |
|-----------|----------|---------|
| `SuspiciousSignal` | `foundation.py:470` | Signal emitted by hunters, carries trace and guard data |
| `TraceStep` | `foundation.py:668` | Single step in source-to-sink trace (`role`: source/propagation/transform/guard/sink) |
| `GuardInfo` | `foundation.py:706` | Guard found along trace path (`effectiveness`: effective/partial/bypassable) |
| `SignalCategory` | `foundation.py:387` | 40+ signal categories across memory, injection, web, auth, crypto |
| `InputChannel` | `schemas.py:118` | Source classification (network, file_input, web_content, repo_checkout, ci_artifact, local_unprivileged, unknown) |
| `ThreatModel` | `foundation.py:99` | Trust boundaries, attacker capabilities, scope |
| `ThreatModelProfile` | `threat_model_profile.py:41` | Execution contexts, attacker capabilities, assets |
| `Finding` | `schemas.py:624` | Confirmed finding with disposition, proof checklist, policy decision |
| `ProofChecklist` | `schemas.py:430` | Tri-state proof items (PROVEN/DISPROVEN/UNKNOWN) |
| `ChecklistStatus` | `schemas.py:71` | `PROVEN`, `DISPROVEN`, `UNKNOWN` |
| `VerdictRecord` | `calibration.py:19` | Specialist verdict with outcome tracking (TP/FP/TN/FN) |
| `SpecialistStats` | `calibration.py:33` | Per-specialist accuracy, precision, recall, dismissal rates |
| `CalibrationStore` | `calibration.py:129` | Persistent storage for calibration data (verdicts.jsonl, stats.json, alerts.jsonl) |
| `SignalFlowTracker` | `signal_flow_tracker.py:26` | Tracks signal progression through pipeline, produces health report |
| `SignalTrace` | `signal_flow_tracker.py:13` | Per-signal stage history with final_disposition and drop_reason |
| `CampaignState` | `state.py:169` | Central state: hypotheses, signals, confirmed_findings, dismissed, wave_history |
| `Entrypoint` | `state.py:114` | Discovered entry point with `auth_required: Optional[bool]` |
| `Evidence` | `schemas.py:555` | Evidence bundle with input_channel, auth_gates, dataflow_snippet |

### Existing Capabilities (what already works)

- **Guard classification**: `GuardInfo` has `effectiveness` field with values `effective|partial|bypassable` and `bypass_reason` (foundation.py:713-714)
- **Trace quality scoring**: `compute_trace_quality()` scores 0.0-1.0 based on source/sink presence, step validity, guard evidence, step count (foundation.py:499-534)
- **Specialist calibration**: `CalibrationStore` tracks TP/FP/TN/FN per specialist, `ConfidenceCalibrator` weights verdicts by trust (0.5-1.5), triggers cross-validation for low-trust specialists (calibration.py, overseer.py:2259-2265)
- **Input channel inference**: 2-signal-minimum conservative inference for network, file_input, web_content, repo_checkout (input_channel_inference.py)
- **Threat model gating**: `ThreatModelProfile` defines attacker capabilities, `_CAPABILITY_TO_CHANNELS` maps capabilities to channels (threat_model_prompt_block.py:12-20)
- **Proof checklist**: Tri-state `ChecklistStatus` with `allow_unknown_in_checklist` config (schemas.py:504-505)
- **Signal flow tracking**: `SignalFlowTracker` records stage/result/detail per signal, produces health report with disposition/drop/parse/persist stats (signal_flow_tracker.py)
- **Entrypoint auth tracking**: `Entrypoint.auth_required: Optional[bool]` (state.py:124)
- **BY_DESIGN classification**: Triager can classify as BY_DESIGN, tracked in signal flow as `dismissed/by_design` (overseer.py:1804)

---

## Tier 1: Foundation

### #11 — Unknown State Promotion

**What wrong assumption currently exists:**

`GuardInfo.from_dict()` defaults `effectiveness` to `"effective"` (foundation.py:735). When the DataflowTracer or a Specialist finds a guard but cannot determine what it does, the system records it as effective. Downstream, the Triager sees "guard present, marked effective" and treats the path as protected.

Similarly, `compute_trace_quality()` awards +0.1 for guards that have a `code_snippet` (foundation.py:527), regardless of whether effectiveness was actually evaluated or silently defaulted. The system treats "I didn't check" the same as "I checked and it's fine."

**What new rule replaces it:**

Every evidence dimension gets an explicit `unknown` state, and **unknown never clears a path on its own.** Two distinct states:

- `unknown` — we looked at something but cannot justify its effect
- `unverified` — the proof step itself has not been completed

Guard effectiveness defaults to `"unknown"`, not `"effective"`. The principle: **absence of evidence is evidence of absence of analysis, not evidence of safety.**

**Where this connects to existing code:**

- `GuardInfo.effectiveness` field (foundation.py:713) — currently `"effective" | "partial" | "bypassable"`, add `"unknown"` as fourth value and new default
- `GuardInfo.from_dict()` default (foundation.py:735) — change from `"effective"` to `"unknown"`
- `compute_trace_quality()` guard scoring (foundation.py:526-528) — unknown-effectiveness guards receive no protective credit
- `ChecklistStatus` enum (schemas.py:71) — already has `UNKNOWN`, but `allow_unknown_in_checklist` (schemas.py:505) defaults `False` meaning UNKNOWN checklist items block submission. This is correct behavior.
- `SignalFlowTracker.record_drop()` (signal_flow_tracker.py:68) — add `"dismissed_with_unknowns"` as trackable drop reason
- Triager prompt (overseer.py:2586-2613) — add UNKNOWN ITEMS section when guards or preconditions haven't been evaluated

**What decisions in the pipeline will now change:**

- `compute_trace_quality()`: unknown-effectiveness guards receive no protective credit (contribute 0 to score, not +0.1)
- Triager prompt receives explicit "UNKNOWN ITEMS" warnings when guards or preconditions haven't been evaluated
- Devil's Advocate specifically challenges findings where unknowns were smoothed over
- `SignalFlowTracker` records `"dismissed_with_unknowns"` so the health report flags dismissals that relied on unverified assumptions

**What types of mistakes this should reduce:**

A major source of missed findings is treating the presence of a guard as proof that the guard is effective. This change prevents the system from converting "there's a `sanitize()` call" into "this path is safe" without actually verifying what the guard does.

**How you will know it worked:**

- `unknown` classifications become visibly present where the system previously forced certainty
- Previously dismissed signals are re-opened when the dismissal depended on unevaluated guards
- Dismissals with unresolved uncertainty become measurable and reviewable through the signal flow health report

---

### #4 — Guard Effectiveness Rigor

**What wrong assumption currently exists:**

Guards are recorded as present or absent, and their `effectiveness` field is filled by the LLM with one of three values: `effective`, `partial`, `bypassable` (foundation.py:713). But the system has no way to verify or challenge those labels. A Specialist can write `"effectiveness": "effective"` with no code evidence and no bypass analysis, and the pipeline accepts it at face value.

The specialist prompts in subagents.py request guards with the format:
```
{"effectiveness": "effective|partial|bypassable", "bypass_reason": "<if bypassable>"}
```
But `bypass_reason` is only populated when effectiveness is `bypassable`. There is no requirement to explain *why* a guard is effective — only why it's bypassable.

**What new rule replaces it:**

Guard effectiveness becomes a four-level classification with evidence requirements:

- **Effective** — requires `code_snippet` showing the guard constrains attacker-controlled value, plus explanation of why bypass is not feasible
- **Partial** — requires identification of what the guard blocks and what it lets through
- **Bypassable** — requires concrete bypass description (existing `bypass_reason` field)
- **Unknown** — default when any of the above evidence is missing

Structural validation rules (system-enforced, not LLM-claimed):
- A guard without a `code_snippet` is automatically `unknown` (no matter what the LLM claims)
- A guard marked `effective` without explaining why bypass fails is downgraded to `unknown`

**Where this connects to existing code:**

- `GuardInfo` dataclass (foundation.py:706-737) — add validation logic or post-processing
- `SuspiciousSignal.guards` list (foundation.py:489) — guards are stored as dicts, validated lazily
- `compute_trace_quality()` guard scoring (foundation.py:526-528) — already checks `any(g.get("code_snippet") for g in self.guards)` but awards credit uniformly
- Specialist prompts (subagents.py) — each specialist requests guard data with `effectiveness` field; prompt wording can require bypass-resistance explanation for `effective` claims
- `overseer.py:2308-2339` — where specialist output is parsed and guard data flows through
- `CalibrationStore` (calibration.py:129) — can track a new metric: guard downgrade rate

**What decisions in the pipeline will now change:**

- Guard classification becomes system-validated: `compute_trace_quality()` and a new validation step enforce evidence requirements before accepting effectiveness claims
- Specialists must provide evidence for `effective` — missing evidence triggers automatic downgrade to `unknown`
- Triager sees guards labeled with validated effectiveness, not raw LLM claims
- Cross-validation is triggered when a signal has multiple guards all marked `effective` but the specialist's verdict is still "vulnerable" — that contradiction gets flagged
- `CalibrationStore` tracks guard downgrade rate per specialist

**What types of mistakes this should reduce:**

False negatives caused by over-crediting guards. Pattern: a Specialist finds a real vulnerability, traces it to a sink, but also finds a validation call along the path. It marks the guard `effective` because the function name sounds protective (`validate_input`, `sanitize_html`, `check_permissions`). The Triager sees the effective guard and dismisses the finding. In reality, the guard might check the wrong field, apply incomplete sanitization, or be bypassable through encoding.

**How you will know it worked:**

- The rate of `effective` guard classifications drops as the system stops accepting unsupported claims
- Findings that survive triage have guards with concrete evidence attached, not just labels
- Guard downgrade rate is trackable: how often the system's structural validation overrides the LLM's initial classification

---

### #10 — Evaluation Discipline

**What wrong assumption currently exists:**

The system has no way to answer "did that change make things better?" The `CalibrationStore` tracks per-specialist accuracy (calibration.py:33-93), and the `SignalFlowTracker` tracks pipeline progression (signal_flow_tracker.py:26-136). But there is no scan-level measurement that combines these into a single assessment of pipeline quality. `TriageMetrics` (schemas.py:592-599) captures raw/triaged/reportable counts and timeout rates, but does not capture disposition quality, unknown burden, or guard evidence rates.

Changes to prompts, thresholds, guard rules, or hunter strategies are made and deployed without baseline comparison. Improvements are assumed, not demonstrated. Regressions are invisible until a user notices a missing finding.

**What new rule replaces it:**

Every scan produces a structured **evaluation record** that can be compared against prior scans. The evaluation record extends the existing `SignalFlowTracker.summary()` output (signal_flow_tracker.py:86-136) with:

- **Signal yield per stage**: how many signals entered each pipeline stage, how many survived (already partially tracked by `by_disposition` and `by_drop_stage` in `summary()`)
- **Disposition distribution**: ratio of SECURITY_VULNERABILITY / HARDENING / BY_DESIGN / DISMISSED (already tracked in `by_classification`)
- **Unknown burden**: how many decisions involved unresolved `unknown` states (new, from #11 and #4)
- **Guard evidence rate**: fraction of guards with validated evidence vs defaulted to unknown (new, from #4)
- **Time-to-verdict per signal**: how long each pipeline stage took (partially available from `VerdictRecord.analysis_time_seconds` in calibration.py:25)
- **Specialist divergence**: how often cross-validation produced disagreement (trackable from existing arbiter flow in overseer.py:2386-2476)

**Where this connects to existing code:**

- `SignalFlowTracker.summary()` (signal_flow_tracker.py:86-136) — extend with new metrics fields
- `SignalFlowTracker.summary_text()` (signal_flow_tracker.py:138-166) — extend human-readable output
- `SignalFlowTracker.print_report()` (signal_flow_tracker.py:168+) — extend health report
- `CalibrationStore` (calibration.py:129) — already persists stats.json and verdicts.jsonl; evaluation record should be written alongside these
- `CampaignState` (state.py:169) — already tracks `confirmed_findings`, `dismissed`, `wave_history`; evaluation record summarizes these
- `TriageMetrics` (schemas.py:592-599) — existing metrics model, evaluation record extends this
- Overseer finalization (overseer.py final phase) — where `signal_tracker.print_report()` is already called; evaluation record is written here

**What decisions in the pipeline will now change:**

- No pipeline change is deployed without a before/after comparison on at least one scan. The evaluation record is the acceptance test
- The signal flow health report is extended to include unknown burden and guard evidence metrics
- Specialist calibration alerts are tied to evaluation data
- The system can detect regression: if a repo that previously produced 5 confirmed findings now produces 0, that is flagged as anomalous

**What types of mistakes this should reduce:**

Meta-mistakes — changes that make the system worse without anyone noticing. Prompt tweaks that raise the dismissal rate. Threshold adjustments that filter legitimate signals. New hunters that generate noise without true positives.

**What the evaluation record proves and does not prove:**

The evaluation record measures pipeline behavior, consistency, productivity, and regression. It does not measure objective security ground truth by itself.

- "Finding count went up" means the pipeline is producing more output. It does not mean the output is more correct.
- "Dismissal rate went down" means the pipeline is filtering less. It does not mean the filtering was wrong before.
- "Unknown burden went up" means the pipeline is being more honest about uncertainty. Whether that honesty leads to better outcomes is measured by comparing against known findings, benchmarked cases, or manual review.

The evaluation record is internal performance evidence. Ground-truth validation is a separate concern that requires external reference data.

**How you will know it worked:**

- You can answer "is the system better this week than last week" with data
- When a change to #11, #4, or any later item is deployed, the evaluation record shows measurable movement
- Regressions are caught within one scan cycle instead of discovered weeks later

---

## Tier 2: Semantics

### #1 — Expected Behavior Model

**What wrong assumption currently exists:**

When the Triager decides `BY_DESIGN` vs `SECURITY_VULNERABILITY` (overseer.py:2602-2606), it reasons from code and a general threat model. But the threat model (foundation.py:99-107) describes *who the attacker is* — trust boundaries, attacker capabilities, scope. It does not describe *what the application is supposed to do*. There is no reference document that says "this endpoint is public and read-only" or "this endpoint is admin-only and can delete resources."

The ThreatModeler subagent (subagents.py:146+) produces a threat_model.json during the foundation phase. Looking at actual output (e.g., `data/projects/78b657f9/memories/foundation/threat_model.json`), it contains `trust_boundaries`, `attacker_capabilities`, `attack_surface`, `in_scope_paths`, `out_of_scope_paths`, and `high_value_targets`. None of these describe endpoint-level intent.

The `Entrypoint` model (state.py:114-126) records `type`, `method`, `path`, `handler`, `file_path`, `line_number`, `parameters`, and `auth_required`. This is structural metadata about where endpoints are — not what they're supposed to do.

**What new rule replaces it:**

The foundation phase produces an **endpoint intent map** alongside the existing threat model. This is a second structured artifact from the ThreatModeler analysis pass, recording for each discovered entrypoint:

- **Visibility**: public / authenticated / admin / internal (extends `Entrypoint.auth_required` from boolean to a classification)
- **Allowed operations**: read / write / delete / execute
- **User-controlled parameters**: which parameters are expected to be user-supplied
- **Sensitive resources**: what the endpoint accesses that is considered sensitive
- **Confidence**: `explicit` (from decorators/annotations) vs `inferred` (from naming/context)

The intent map is descriptive, not prescriptive. It records what the codebase appears to intend based on structural evidence.

**BY_DESIGN classification standard:**

The confidence level of the intent map entry determines how much weight it carries in classification:

- **Explicit intent** (from decorators, annotations, access control config) can strongly support `BY_DESIGN`. Example: `@public_api` decorator on an endpoint that exposes data — the code explicitly marks this as intended public access.
- **Inferred intent** (from naming, context, module structure) can support `BY_DESIGN` only when corroborated by other evidence — such as consistent patterns across sibling endpoints, documentation, or absence of any guard suggesting the behavior was meant to be restricted.
- **Risky behavior with only inferred intent should stay contestable.** If the intent map says "this endpoint is probably public" based on naming alone, and the endpoint performs a destructive operation (delete, write, execute), the inferred intent is not strong enough to clear `BY_DESIGN`. The finding should remain open or be classified with a flag indicating the intent basis was weak.

This prevents the system from moving the old problem into a more structured artifact: instead of "LLM guessed this was intended" → "intent map inferred this was intended." The structured outfit does not change the strength of the evidence.

**Where this connects to existing code:**

- `Entrypoint` model (state.py:114-126) — extend with intent fields or create companion structure
- `FoundationContext` (foundation.py:110-142) — already carries `repo_profile`, `scope_map`, `threat_model`; add `endpoint_intent_map`
- `FoundationContext.to_prompt_context()` (foundation.py:189+) — serialize intent map for agent prompts
- ThreatModeler subagent prompt (subagents.py:146+) — extend to produce intent map output
- EntrypointHunter output — already discovers entrypoints; intent classification builds on this
- Triager prompt (overseer.py:2586-2613) — include intent map entry for the endpoint being triaged
- `SignalFlowTracker` — track `by_design_with_intent_reference` vs `by_design_without_intent_reference`

**What decisions in the pipeline will now change:**

- Triager must cite which intent map entry supports a `BY_DESIGN` classification. A `BY_DESIGN` without a matching intent map entry gets flagged in the evaluation record (#10)
- Devil's Advocate can challenge `BY_DESIGN` dismissals by checking whether the cited intent map entry actually matches the observed behavior
- Specialists receive intent map context for the endpoint they're analyzing
- Signal flow health report tracks `by_design_with_intent_reference` vs `by_design_without_intent_reference`

**What types of mistakes this should reduce:**

Incorrect `BY_DESIGN` classifications where the Triager narratively convinces itself that dangerous behavior was intentional. Example: an endpoint that allows unauthenticated file deletion. Without an intent map, the Triager might reason "this is probably an admin cleanup endpoint." With an intent map showing the endpoint is public and read-only, the mismatch becomes a signal.

**How you will know it worked:**

- `BY_DESIGN` classifications without intent map references become visible and countable
- When the same repo is scanned twice, `BY_DESIGN` decisions reference the same intent map entries rather than depending on which narrative the LLM generated
- The intent map is reviewable as a standalone artifact

---

### #2 — Policy Baseline Deviation Detection

**What wrong assumption currently exists:**

The system finds vulnerabilities by looking at individual code paths in isolation. A Specialist examines one endpoint, decides whether it's vulnerable, and moves on. The existing `TriagePolicy` (schemas.py:233-261) defines filtering rules (filter_third_party, filter_tests, evidence_gates) but operates on individual findings, not on comparisons between endpoints.

The system has no concept of "what's normal here" and therefore cannot detect "what's abnormal." If 9 out of 10 CRUD handlers check ownership, and the 10th doesn't, no signal is generated because no hunter is looking for that pattern.

**What new rule replaces it:**

After the foundation phase produces the intent map (#1), a new deterministic analysis step builds a **protection baseline** for groups of similar endpoints. "Similar" means: same resource type, same route prefix, same controller/module, or same decorator pattern.

For each group, the baseline records which guards are consistently present. Endpoints that deviate from their group's baseline — missing a guard all siblings have — are emitted as `policy_deviation` signals.

This is a deterministic comparison step. The LLM identified the endpoints and their guards; the system compares them mechanically. The deviation itself is the signal — the Specialist and Triager still do verification.

**Where this connects to existing code:**

- `Entrypoint` model (state.py:114-126) — grouped by route prefix, handler module, or type
- `Evidence.auth_gates` (schemas.py:573) — existing field tracking auth decorators/checks per endpoint
- `SignalCategory` enum (foundation.py:387) — add `POLICY_DEVIATION` category
- `CATEGORY_TO_FAMILY` mapping (registry.py:75-147) — route `POLICY_DEVIATION` to `AUTHZ_BUSINESS_LOGIC` family
- `SuspiciousSignal` (foundation.py:470) — deviation signals carry the specific guard that's missing and the sibling endpoints that have it
- `SignalFlowTracker` — track deviation signals separately in the health report
- Runs after foundation phase completes and entrypoints are discovered, before or during hunting phase

**What decisions in the pipeline will now change:**

- New signal source enters Stage 1.5: `policy_deviation` signals from baseline comparison
- Specialists receiving deviation signals get different framing: "verify whether endpoint X should have guard Y, given that endpoints A, B, C all have it"
- Triager can use deviation signals as convergent evidence for other findings
- Evaluation record (#10) tracks deviation signals: generated vs survived triage vs confirmed

**What types of mistakes this should reduce:**

Missed authorization and logic vulnerabilities invisible to sink-based analysis. The classic example: IDOR. There is no dangerous function to find. There is just a missing ownership check on one endpoint that every sibling has. Sink hunters will never find this.

**How you will know it worked:**

- Deviation signals are generated for endpoints structurally different from siblings
- Authorization bugs previously invisible start appearing in scan results
- False positive rate for deviation signals is trackable via #10

---

### #6 — Behavioral Sinks

**What wrong assumption currently exists:**

The system defines sinks as dangerous functions: `eval()`, `subprocess.run()`, `cursor.execute()`, `innerHTML`. The SinkHunter subagent prompts (subagents.py) instruct hunters to find these function names. The `SuspiciousSignal.sink_function` field (foundation.py:482) captures the specific function.

But many high-impact vulnerabilities don't involve a single identifiable dangerous function. IDOR is "user controls which object is accessed" — the sink might be `db.query(Model).get(id)`, a perfectly safe function. SSRF is "user controls where the system connects" — the sink might be `requests.get(url)`, an ordinary HTTP call. These are safe functions used in contexts where attacker-controlled input determines what resource is accessed.

The `SignalCategory` enum (foundation.py:387-457) includes `IDOR`, `SSRF`, `PATH_TRAVERSAL` as categories. The `CATEGORY_TO_FAMILY` mapping (registry.py:120, 99, 114) routes these to appropriate specialist families. But the *hunters* that generate these signals are still looking for function names, not for patterns of attacker control. The specialist knows how to verify an IDOR — but the hunter doesn't know how to find one.

**What new rule replaces it:**

The sink model expands from "dangerous functions" to "dangerous capabilities." A behavioral sink is defined by what the attacker controls through it:

- **Selector control** — attacker determines which object/record is accessed (IDOR class)
- **Destination control** — attacker determines where the system connects (SSRF class)
- **Path control** — attacker determines which file is accessed (traversal class)
- **Interpretation control** — attacker determines what gets executed/evaluated (injection classes — overlaps with existing function-based sinks)
- **Boundary control** — attacker determines what data leaves the trust boundary (data exposure class)

These behavioral categories map to existing `SignalCategory` values: `IDOR`, `SSRF`, `PATH_TRAVERSAL`, injection categories, `SENSITIVE_DATA_EXPOSURE`. The change is in hunter prompts and detection strategy, not in the routing pipeline.

**Where this connects to existing code:**

- SinkHunter prompts (subagents.py) — extend to look for patterns of control, not just function names
- `SignalCategory` enum (foundation.py:387) — already has `IDOR`, `SSRF`, `PATH_TRAVERSAL`, `SENSITIVE_DATA_EXPOSURE`; no new categories needed for the core behavioral sinks
- `CATEGORY_TO_FAMILY` (registry.py:75-147) — routing already exists for these categories
- `SuspiciousSignal.sink_function` (foundation.py:482) — for behavioral sinks, this field captures the point of control rather than a dangerous function
- Specialist prompts (subagents.py) — IDOR, SSRF, path traversal specialists already exist and know how to verify these issues. The gap is upstream: getting signals to them
- `TraceStep.role` (foundation.py:677) — `"sink"` role is already defined; behavioral sinks use the same role, but the sink is the point where attacker-controlled input determines resource access

**What decisions in the pipeline will now change:**

- Hunters emit signals for code currently invisible: any place where attacker-controlled value is used as a selector, destination, path, or boundary-crossing payload
- DataflowTracer traces from source to *point of control*, not necessarily to a known dangerous function
- `compute_trace_quality()` applies same scoring to behavioral traces
- Evaluation record (#10) tracks behavioral sink signals separately from function-based sink signals

**What types of mistakes this should reduce:**

Entire vulnerability classes the system cannot currently detect because they don't involve function-name-matchable sinks. IDOR is consistently one of the most impactful and most common web vulnerabilities, and a system that only looks for dangerous functions will never find it.

**How you will know it worked:**

- The system produces signals for vulnerability classes it previously had zero coverage on
- Behavioral sink signals enter the pipeline and some survive triage as confirmed findings
- On a repository with a known IDOR bug, the system finds it

---

## Tier 3: Proof Depth

### #3 — Precondition Proof

**What wrong assumption currently exists:**

The proof model is: "attacker-controlled data reaches a dangerous sink." The `TraceStep` schema (foundation.py:668-702) captures source→propagation→transform→guard→sink. If the trace is complete and guards are ineffective, the finding is confirmed.

But the trace proves data flow — it does not prove the attacker can actually initiate that flow. A trace through an admin-only endpoint is technically valid but unexploitable by an anonymous attacker. The `Entrypoint.auth_required` field (state.py:124) is `Optional[bool]` — a simple flag, not a structured precondition assessment. The `Evidence.auth_gates` field (schemas.py:573) collects auth decorator names as strings, but these aren't evaluated against the threat model's attacker capabilities.

The `ThreatModelProfile.attacker_capabilities` (threat_model_profile.py:22-29) defines what attackers can do (`remote_network`, `remote_web_content`, etc.), and the `_CAPABILITY_TO_CHANNELS` mapping (threat_model_prompt_block.py:12-20) connects capabilities to input channels. But there is no structured comparison between "what the attacker can do" and "what is required to reach this code path."

**What new rule replaces it:**

Every confirmed finding must include a **precondition assessment** alongside its data flow trace. Preconditions fall into four categories:

- **Authentication state** — can an anonymous user reach this path? Checked against `ThreatModelProfile.attacker_capabilities` and `Entrypoint.auth_required`
- **Authorization requirements** — does the path require a specific role or ownership? Checked against `Evidence.auth_gates` and the intent map (#1)
- **Workflow/state gating** — does the path require prior state (completed payment, verified email)?
- **Timing/ordering** — does exploitation require specific request ordering or race windows?

Each precondition is classified as `satisfied` (attacker can meet it), `unsatisfied` (cannot under threat model), `conditional` (can under some configurations), or `unknown` (not evaluated — per #11, unknown never clears a path on its own).

**Where this connects to existing code:**

- `TraceStep` (foundation.py:668) — does not need schema change; preconditions are on the signal, not on individual trace steps
- `SuspiciousSignal` (foundation.py:470) — add `preconditions: list[dict]` field alongside existing `trace_steps` and `guards`
- `SuspiciousSignal.to_specialist_context()` (foundation.py:536) — include preconditions section in specialist context
- `Entrypoint.auth_required` (state.py:124) — existing field provides one input to precondition assessment
- `Evidence.auth_gates` (schemas.py:573) — existing field provides decorator-level auth evidence
- `ThreatModelProfile.attacker_capabilities` (threat_model_profile.py:22-29) — defines what attacker can do; precondition assessment compares against this
- Specialist output schema (subagents.py) — extend to include `preconditions` list
- Triager prompt (overseer.py:2586-2613) — include precondition assessment in classification context

**What decisions in the pipeline will now change:**

- Specialists identify preconditions for the vulnerability, output includes `preconditions` list
- Triager evaluates preconditions against threat model: all `satisfied` = SECURITY_VULNERABILITY, valid flow but `unsatisfied` = HARDENING, `unknown` preconditions get flagged
- Devil's Advocate can challenge precondition assessments
- Evaluation record (#10) tracks precondition distribution across findings

**What types of mistakes this should reduce:**

Two failure modes. False positives: technically valid trace but attacker cannot reach the entry point. False negatives: finding dismissed with narrative reasoning about reachability ("this probably requires admin") without structured verification.

**How you will know it worked:**

- Findings include precondition assessments matching threat model
- `HARDENING` classification becomes more precise: specifically "real issue, attacker can't reach it"
- Fewer narrative-based dismissals about reachability

---

### #5 — Expanded Source Model

**What wrong assumption currently exists:**

The `InputChannel` enum (schemas.py:118-133) defines six source types. The `input_channel_inference.py` service detects these by matching code patterns: HTTP route registrations, file upload APIs, DOM sinks, repo content ingestion. The `_CAPABILITY_TO_CHANNELS` mapping (threat_model_prompt_block.py:12-20) connects attacker capabilities to these channels.

But attacker-controlled data frequently enters through channels not in this model:

- **Stored user data** — a database field originally user-submitted. Current system sees `db.query()` as trusted, not as attacker-controlled source
- **Webhooks/callbacks** — third-party payloads where attacker controls the external account
- **Message queues** — event consumed from queue, enqueued by user-facing service
- **HTTP metadata** — `Host`, `Referer`, `X-Forwarded-For`, cookie values beyond route params

The `Entrypoint.type` field (state.py:117) already includes `message_consumer` as a type, showing the model conceptually recognizes queue consumers as entry points. But `InputChannel` has no corresponding value, and `input_channel_inference.py` has no signal collectors for queue-based sources.

**What new rule replaces it:**

New `InputChannel` values:

- `stored_user_data` — data read from DB/cache originally user-submitted
- `webhook_callback` — payloads from external services via callback endpoints
- `message_queue` — events consumed from queues/topics/event buses
- `http_metadata` — headers, cookies, transport-level values beyond route params

Each gets signal collectors in `input_channel_inference.py` following the existing 2-signal-minimum pattern.

The `ThreatModelProfile` (threat_model_profile.py:41) gains corresponding `AttackerCapability` values: `can_influence_stored_data`, `can_trigger_webhook`, `can_enqueue_messages`. These default to not included — conservative by default, following the pattern where `untrusted_repo_content` and `untrusted_ci_artifact` are opt-in.

The `_CAPABILITY_TO_CHANNELS` mapping (threat_model_prompt_block.py:12-20) extends to connect new capabilities to new channels.

**Where this connects to existing code:**

- `InputChannel` enum (schemas.py:118-133) — add new values
- `input_channel_inference.py` — add new `_collect_*_signals()` functions following existing pattern
- `ThreatModelProfile` (threat_model_profile.py:22-29) — add `AttackerCapability` values
- `_CAPABILITY_TO_CHANNELS` (threat_model_prompt_block.py:12-20) — extend mapping
- `preset_to_profile()` (threat_model_profile.py:47-78) — decide which presets include new capabilities
- `Entrypoint.type` (state.py:117) — already includes `message_consumer`; ensure webhook and queue handlers are discovered
- `build_threat_model_prompt_block()` (threat_model_prompt_block.py:35-84) — new channels appear in derived attacker-controlled channels

**What decisions in the pipeline will now change:**

- Hunters emit signals for code paths where source is a database read, queue consumer, or webhook handler
- DataflowTracer traces from newly recognized sources to sinks
- Triager checks new source channels against threat model
- Input channel inference gains new signal collectors with same 2-signal threshold

**What types of mistakes this should reduce:**

Missed vulnerabilities where attacker data enters through non-obvious channels. Stored XSS (user submits script in profile field, different endpoint renders it), second-order SQL injection (stored value used in later query), webhook-triggered SSRF.

**How you will know it worked:**

- New `InputChannel` values appear in signal flow health report
- On repos with stored XSS or second-order injection, the system traces from storage write through DB read to unsafe render

---

## Tier 4: Operational Realism

### #7 — Reachability Awareness

**What wrong assumption currently exists:**

The system treats all code paths as equally reachable. The `FoundationContext.is_in_scope()` method (foundation.py:161-183) filters paths against test/vendor/generated patterns, but this is binary: in-scope or not. There is no intermediate classification for debug-mode-only endpoints, feature-flag-gated code, or dead code.

The `Finding.config_dependent` field (schemas.py:647) and `Finding.config_flag` (schemas.py:648) already capture configuration dependency at the finding level. But this is set during triage, not during signal generation. Signals from debug-only code enter the pipeline at the same priority as production signals.

The existing `ScopeDepth` enum (state.py:77-83) tracks analysis depth (UNTOUCHED→MAPPED→HUNTED→TRACED→AUDITED) but not reachability.

**What new rule replaces it:**

Every signal carries a **reachability classification**:

- **Production-reachable** — runs in normal production operation
- **Config-dependent** — runs only with specific config/feature flag/env var. Maps to existing `Finding.config_dependent` and `Finding.config_flag` fields
- **Debug/test-only** — gated behind debug mode or only called from test files. Filtered by `FoundationContext.is_in_scope()` for test files, but in-scope debug endpoints need explicit labeling
- **Unreachable** — no live callers (dead code). Requires evidence of unreachability
- **Unknown** — not evaluated. Per #11, does not clear the finding

**Where this connects to existing code:**

- `SuspiciousSignal` (foundation.py:470) — add `reachability: str` field
- `Finding.config_dependent` / `Finding.config_flag` (schemas.py:647-648) — already exist; `config_dependent` maps to reachability
- `FoundationContext.is_in_scope()` (foundation.py:161-183) — already filters test/vendor; can be extended to provide reachability hints
- `ScopeMap` (foundation.py:89-95) — already has `test_code`, `vendor_code`, `generated_code` lists
- Specialist output — set reachability during verification
- Signal pipeline priority — `config_dependent` and `debug_test_only` signals are deprioritized

**What decisions in the pipeline will now change:**

- `debug_test_only` signals deprioritized; production-reachable signals go first
- Triager uses reachability as severity modifier
- Evaluation record tracks findings by reachability class
- Signal flow health report shows dismissals due to reachability vs other reasons

**What types of mistakes this should reduce:**

False positives from unreachable code. Misclassified severity where a debug-only vulnerability is reported at the same severity as a production one.

**How you will know it worked:**

- Findings include reachability classifications matching reality
- False positive rate drops for repos with significant test/debug code
- Reviewers stop encountering findings in test files or debug endpoints

---

## Tier 5: Coverage Expansion

### #8 — Diversified Signal Generation

**What wrong assumption currently exists:**

All signals currently come from two sources: sink hunters (dangerous functions) and entrypoint hunters (HTTP routes). Both look for specific patterns. If a vulnerability doesn't involve a recognizable sink or standard entry point, no signal is generated.

The `SignalFlowTracker` (signal_flow_tracker.py) tracks `signals_entered` but does not distinguish signals by source type. There is no way to measure which signal sources are productive.

**What new rule replaces it:**

New signal sources supplement existing hunters:

- **Inconsistency signals** — from deviation detector (#2), already covered
- **Error-path signals** — hunter examining `catch`/`except`/`rescue`/`fallback` branches for security-relevant operations that appear only in error paths
- **Trust-boundary-crossing signals** — hunter identifying outbound data flows (API calls, response bodies, log sinks, email content) checking for sensitive data without redaction
- **Configuration-conditional signals** — code paths gated by env vars, feature flags, debug settings

All new signals enter the same pipeline with the same proof bar.

**Where this connects to existing code:**

- SinkHunter prompts (subagents.py) — new hunter prompts for error-path, boundary-crossing, config-conditional detection
- `SignalCategory` enum (foundation.py:387) — may need new categories or reuse existing ones (`SENSITIVE_DATA_EXPOSURE`, `INSECURE_CONFIGURATION`)
- `SignalFlowTracker` (signal_flow_tracker.py) — extend to track `signal_source` per signal (sink_hunter, entrypoint_hunter, error_path, boundary_crossing, config_conditional, policy_deviation, pattern_match)
- `HUNT_FOCUSES` structure (foundation.py:19-52) — add focus types for new signal sources
- Existing wave dispatch system — new hunters can run as additional wave tasks

**What decisions in the pipeline will now change:**

- Signal flow health report tracks per-source signal yield and true-positive rate
- Specialists receiving error-path or boundary-crossing signals get different framing
- Evaluation record tracks per-source true-positive rate for refinement decisions

**What types of mistakes this should reduce:**

Missed vulnerabilities outside the sink-hunting paradigm. Information disclosure through verbose error messages. Credential leakage through debug logging. Validation bypass in exception handlers. Sensitive data in outbound API calls.

**How you will know it worked:**

- New signal sources produce signals that survive triage
- Signal source distribution shifts from 100% sink/entrypoint to a spread
- Per-source true-positive rate is trackable for investment decisions

---

## Tier 6: Learning Loop

### #9 — Learning from Confirmed Findings

**What wrong assumption currently exists:**

Every scan starts from zero. The `CampaignState` (state.py:169) tracks `confirmed_findings` and `dismissed` within a scan, but confirmed findings are not converted into search templates. The `CalibrationStore` (calibration.py:129) tracks specialist accuracy, but not vulnerability patterns.

The `CampaignState._signal_fingerprints` set (state.py:227) deduplicates signals by `(file_path, line_start, category)`. This is dedup, not pattern matching — it prevents the same signal from being processed twice, but does not use confirmed signals to find siblings.

**What new rule replaces it:**

When a finding is confirmed (`SECURITY_VULNERABILITY`), the system extracts a **risk pattern**:

- **Code shape** — syntactic pattern (e.g., "`.extra(where=[user_input])`")
- **Guard absence** — which guard was missing or ineffective
- **Precondition profile** — what preconditions were satisfied (#3)
- **Source-to-sink shape** — abstracted data flow

Risk patterns are stored per-repository and per-category. After extraction, a deterministic search runs across the codebase looking for the same pattern. Matches enter the pipeline as `pattern_match` signals.

**Where this connects to existing code:**

- `CampaignState.confirmed_findings` (state.py:226) — source of confirmed findings to extract patterns from
- `SuspiciousSignal.to_dict()` (foundation.py:620) — serialized signal data used for pattern extraction
- `SignalCategory` — patterns are grouped by category
- `CampaignState._signal_fingerprints` (state.py:227) — pattern matches must not duplicate already-processed signals
- `SignalFlowTracker` — track `pattern_match` as a signal source
- Overseer wave loop — pattern matching runs after a finding is confirmed, before next wave

**What decisions in the pipeline will now change:**

- After confirmation, deterministic search finds siblings; matches enter as `pattern_match` signals
- Specialists receiving pattern matches get confirmed finding as context
- Triager uses pattern provenance as strengthening evidence
- Evaluation record tracks "findings discovered via pattern match" vs "via hunting"

**What types of mistakes this should reduce:**

Missed sibling vulnerabilities — same bug repeated across multiple endpoints. Currently, finding siblings depends on the hunter scanning the right file. With pattern matching, confirming one guarantees searching for others.

**How you will know it worked:**

- After confirming a finding, pattern_match signals are generated for siblings
- Some pattern matches survive triage as additional confirmed findings
- On repos with repeated patterns, recall improves after the first confirmation

---

## Disposition Matrix

This is the single canonical decision layer for classification. All factors from #1, #3, #7, #11 combine here. The Triager uses this matrix — not ad-hoc reasoning — to map evidence to disposition.

### Inputs to Classification

| Factor | Source | Values |
|--------|--------|--------|
| Data flow | TraceStep chain | Complete (source→sink) / Partial / None |
| Guard effectiveness | GuardInfo (validated) | Effective / Partial / Bypassable / Unknown |
| Intent match | Intent map (#1) | Matches intent / Contradicts intent / No intent entry / Inferred only |
| Preconditions | Precondition assessment (#3) | All satisfied / Some unsatisfied / Some unknown / All unknown |
| Reachability | Reachability classification (#7) | Production / Config-dependent / Debug-test-only / Unreachable / Unknown |
| Threat model | ThreatModelProfile | Attacker has capability / Attacker lacks capability |
| Unknown burden | Aggregate from above | None / Low (1-2 unknowns) / High (3+ unknowns) |

### Classification Rules

**SECURITY_VULNERABILITY** — all of the following:
- Data flow is complete (source→sink verified)
- Guards are bypassable, partial, or unknown (no effective guard blocks the path)
- Preconditions are satisfied under the threat model (attacker can reach it)
- Reachability is production or config-dependent (with config likely active)
- Threat model includes the required attacker capability
- Intent map either has no entry, or the behavior contradicts the stated intent

**HARDENING** — the behavior is real but one of:
- Preconditions are unsatisfied under the current threat model (attacker can't reach it, but the code is still weak)
- Reachability is config-dependent with config unlikely active in production
- Guard is partial (reduces but doesn't eliminate risk)
- Threat model excludes the required attacker capability, but a broader model would include it

**BY_DESIGN** — requires all of:
- Intent map has an entry with `explicit` confidence that matches the observed behavior, OR
- Intent map has an entry with `inferred` confidence AND corroborating evidence (consistent sibling patterns, documentation, explicit absence of guards across all similar endpoints)
- The behavior is within the stated allowed operations for the endpoint
- The finding does not involve a risky operation (delete, execute, write to sensitive resource) with only inferred intent support

**DISMISSED** — the signal is not a real issue:
- Data flow is disproven (no path from source to sink exists)
- Guard is effective with validated evidence (code snippet + bypass resistance explanation)
- Reachability is established as unreachable with evidence
- The code is in test/vendor/generated scope (already handled by `FoundationContext.is_in_scope()`)

**SPECULATIVE** — the signal requires assumptions to be exploitable:
- Data flow depends on conditions not established in code ("if the attacker bypasses...")
- Preconditions are unknown and the signal lacks other supporting evidence
- The attack scenario requires capabilities not in the threat model and not plausibly obtainable

### Unknown Burden Rules

When unknowns are present, the classification shifts conservatively:

| Unknown factor | Effect on classification |
|---------------|------------------------|
| Guard effectiveness unknown | Cannot dismiss based on guard presence. Signal stays open. |
| Preconditions unknown | Cannot confirm as SECURITY_VULNERABILITY with full confidence. Flag for review. |
| Reachability unknown | Cannot deprioritize. Treat as production-reachable until established otherwise. |
| Intent unknown | Cannot classify as BY_DESIGN. Signal stays open. |
| Multiple unknowns (3+) | High unknown burden. Finding is flagged in evaluation record. Requires manual review or additional analysis before strong classification. |

### Evidence Layer Requirements

Each classification must state which evidence layer supports it (see Evidence Layers section):

- Codebase evidence: what the code says (required for all classifications)
- Threat model interpretation: whether the attacker can exploit it (required for SECURITY_VULNERABILITY vs HARDENING)
- Deployment interpretation: whether it's active in production (required for reachability-based deprioritization)

A classification that depends on deployment interpretation must explicitly state the deployment assumption. "This is debug-only" must cite the gating mechanism (env var, feature flag, conditional compilation), not just the module name or file path.

---

## Signal Provenance and Deduplication

After the changes in this design, the same real issue may be surfaced by multiple sources:

- Behavioral sink hunter finds `db.get(user_supplied_id)` as selector control
- Policy deviation detector finds the endpoint missing an ownership check its siblings have
- Error-path hunter finds the same endpoint's error handler leaks the full query
- Pattern matcher finds a sibling endpoint with the same missing guard

This is good for corroboration but creates three operational problems: noise, inflated metrics, and unclear ownership. The following rules resolve them.

### Merge Rules

Signals are **merged** when they refer to the same code location (file + line range) AND the same vulnerability class (same `SignalCategory` or parent family). Merged signals become a single pipeline entry with multiple provenance tags.

Signals **remain separate** when they:
- Refer to different code locations (even if the same root cause)
- Refer to different vulnerability classes at the same location (e.g., IDOR + data exposure at the same endpoint)
- Come from pattern matching — pattern match signals always remain separate from the original confirmed finding, since they are at different locations

### Corroboration Rules

When multiple signal sources identify the same issue (merged signal), the signal's priority and confidence are strengthened:

| Sources | Effect |
|---------|--------|
| 1 source | Normal priority |
| 2 independent sources | Priority boost: processed before single-source signals of the same severity |
| 3+ independent sources | High-confidence signal: Specialist is informed of convergent evidence |

Corroboration strengthens priority, not disposition. A multi-source signal still goes through the full pipeline and can still be dismissed if the evidence doesn't hold up.

### Metrics Rules

The evaluation record (#10) counts discoveries as follows:

- **Unique findings**: deduplicated by (file_path, line_range, vulnerability_class). This is the primary metric. One real issue = one count, regardless of how many sources found it.
- **Signal yield per source**: how many raw signals each source generated before dedup. This measures source productivity.
- **Source contribution**: for each unique finding, which sources contributed signals. This measures which sources are finding real issues vs generating noise.
- **Corroboration rate**: what fraction of confirmed findings were identified by 2+ independent sources. Higher corroboration rate suggests the signal sources are finding real issues, not noise.

A single issue found by 4 sources counts as 1 unique finding with 4 source contributions. It does not inflate the finding count to 4.

### Provenance Tracking

Every signal entering the pipeline carries a `signal_source` tag:

- `sink_hunter` — traditional function-based sink detection
- `behavioral_sink` — capability-based detection (#6)
- `entrypoint_hunter` — entry point discovery
- `policy_deviation` — baseline comparison (#2)
- `error_path` — error/fallback branch analysis (#8)
- `boundary_crossing` — outbound data flow analysis (#8)
- `config_conditional` — feature-flag/debug-gated code (#8)
- `pattern_match` — sibling of confirmed finding (#9)

The `SignalFlowTracker` (signal_flow_tracker.py) is extended to record `signal_source` on each `SignalTrace` entry, enabling per-source analysis in the health report.

---

## Implementation Dependencies

```
#11 (Unknown State) ──┐
                       ├──→ #10 (Evaluation) ──→ measures all subsequent changes
#4 (Guard Rigor) ─────┘
                               │
                               ▼
#1 (Expected Behavior) ──→ #2 (Deviation Detection) ──→ #6 (Behavioral Sinks)
                               │
                               ▼
#3 (Preconditions) ──→ #5 (Expanded Sources) ──→ #7 (Reachability)
                               │
                               ▼
                    #8 (Diversified Signals) ──→ #9 (Pattern Learning)
```

**Hard dependencies:**
- #2 requires #1 (deviation detection needs intent map)
- #10 should be in place before deploying #1, #2, #6, or later items (measurement first)
- #9 requires confirmed findings to exist (works best after #6 and #8 expand coverage)

**Soft dependencies:**
- #3 benefits from #1 (intent map informs precondition assessment)
- #7 benefits from #10 (reachability false positive rate is trackable)
- #8 benefits from #2 (deviation signals are one of the new sources)

---

## Key Principles (Cross-Cutting)

1. **Unknown never clears a path on its own.** Not "unknown = dangerous", but "unknown = not established either way."
2. **The LLM proposes; the system enforces.** Structural validation rules override LLM claims when evidence is missing.
3. **New signal sources widen visibility; the proof standard does not change.** Every signal goes through the full pipeline.
4. **Pattern match strengthens search, not replaces proof.** Confirmed patterns create high-priority signals, not auto-confirmed findings.
5. **Reachability changes priority, scope, and impact — not silently erases real issues.**
6. **Every change is measurable.** The evaluation record (#10) is the acceptance test for all other items.
