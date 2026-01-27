# LLM-Based Secondary Validation for Triage System

**Date:** 2026-01-27
**Status:** Approved
**Priority:** High - Reduce false positives in triage output

## Problem Statement

The current triage system has a sophisticated 6-disposition classification model with strict evidence requirements, but lacks deep validation of exploitability. Findings can be marked as VALID_SECURITY_ISSUE or BUG based on pattern matching and heuristics, without verifying that:

1. The dangerous code is actually reachable by attackers
2. Attacker-controlled input can actually reach the sink
3. The finding represents a true security issue vs bug vs expected behavior

Examples of false positives:
- `exec()` function exists but isn't reachable from any entry point
- Unsafe patterns in example code or documentation
- Dangerous functions that are working as designed (e.g., eval in template engines)
- Patterns that look exploitable but have no realistic attack scenario

## Solution Overview

Add a **secondary LLM-based validation layer** that uses agentic investigation with tool access (Read, Grep, Glob) to deeply validate findings. This validator runs AFTER classification and applies high criticism to distinguish security issues from bugs/hardening/expected behavior.

**Key Principles:**
- Default to high criticism (fewer false positives preferred)
- Assume NOT exploitable unless proven with evidence
- Validate both reachability AND attacker control
- Configurable and optional (can be disabled)
- Two-tier validation: fast filter + deep investigation

## Architecture

### Current Pipeline (triage_with_protocol)

```
Step 0: ProductionRelevanceFilter (LLM) - filters non-production code + quick validation
Step 1: Evidence gathering (tools) - collects code snippets, symbols, dataflow
Step 2: Classification (rules) - assigns disposition via StrictClassifier
Step 3: ProtocolEvaluator (rules) - applies gates and validates
Step 4: Quest orchestration - gathers missing evidence if needed
```

### New Pipeline

```
Step 0: ProductionRelevanceFilter (LLM) - UNCHANGED - fast filter for obvious false positives
Step 1: Evidence gathering (tools) - UNCHANGED
Step 2: Classification (rules) - UNCHANGED
Step 3a: Pre-validation gates (rules) - NEW - basic sanity checks extracted from ProtocolEvaluator
Step 3b: LLM Validator (agentic) - NEW - deep investigation with tool access
Step 4: Quest orchestration - UNCHANGED
```

### Key Architectural Changes

1. **ProductionRelevanceFilter (Step 0)** - Keep unchanged, serves as fast/cheap first filter
2. **Pre-validation Gates (Step 3a)** - Extract basic gates from ProtocolEvaluator to run before expensive LLM
3. **LLM Validator (Step 3b)** - NEW component, replaces ProtocolEvaluator's validation logic
4. **Output Preserved** - Still produces SubmissionResult + TriageResult for backward compatibility
5. **Report Toggle** - Frontend can show filtered (validated only) or unfiltered (all classified) findings

### Two-Tier Validation Strategy

**Tier 1: ProductionRelevanceFilter (always runs)**
- Fast, cheap LLM call (~300 tokens, $0.01 per finding)
- Catches obvious false positives (test code, examples, documentation)
- Stage 1: Production relevance check
- Stage 2: Quick validation to filter noise

**Tier 2: LLM Validator (optional, enabled by default)**
- Slow, expensive agentic LLM (~10K+ tokens, 4-10 tool calls, $0.10-0.50 per finding)
- Deep investigation of findings that passed Tier 1
- Validates reachability and attacker control with high skepticism
- Uses tools to explore codebase and prove exploitability

## Component Design

### 1. LLM Validator Implementation

**Location:** `/backend/services/validation/llm_validator.py`

**Class: `LLMFindingValidator`**

**Purpose:** Agentic LLM that investigates findings to determine if they're truly exploitable security issues vs bugs/hardening/expected behavior.

**Core Features:**

1. **Agentic Investigation:**
   - Receives finding + evidence + classification + checklist
   - Uses tool calls (Read, Grep, Glob) to explore codebase
   - Uses specialized tools (symbol lookup, dataflow tracing from EvidenceGatherer)
   - Validates reachability and attacker control with high skepticism
   - Returns binary decision: VALID or INVALID with detailed reasoning

2. **Configurable Criticism Level:**
   - **HIGH** (default): Require explicit proof of both reachability AND attacker control
   - **MEDIUM**: Accept strong circumstantial evidence for one dimension
   - **LOW**: Accept weak signals (essentially trust StrictClassifier)

   Criticism level adjusts evidence thresholds, not prompt content.

3. **Input:**
   - Finding object
   - Evidence bundle
   - ClassificationResult (disposition, checklist, reasoning)
   - Threat model profile
   - Criticism level setting

4. **Output:**
   - `ValidationResult(is_valid: bool, reasoning: list[str], categories: list[str])`
   - Categories: "security_issue", "bug", "hardening", "by_design", "expected_behavior"
   - Reasoning explains why (e.g., "exec() not reachable from HTTP entry points")

**Tool Access:**

The validator has access to:
- **Read(file_path)** - Read source files
- **Grep(pattern, glob)** - Search codebase for patterns
- **Glob(pattern)** - Find files by name
- **Specialized tools** - Symbol search, dataflow tracing (from EvidenceGatherer)

**Agentic Loop:**
```python
messages = [{"role": "user", "content": "Begin investigation."}]
max_turns = 10  # Limit tool use rounds

for turn in range(max_turns):
    response = client.messages.create(
        model=model,
        system=validation_prompt,
        messages=messages,
        tools=tools
    )

    if response.stop_reason == "end_turn":
        return parse_validation_response(response.content)

    if response.stop_reason == "tool_use":
        # Execute tools, add results to conversation
        tool_results = execute_tools(response.content)
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
```

### 2. Validation Prompt Design

**Prompt Structure:**

```
You are a security validation expert performing secondary triage on a potential vulnerability.

## Your Mission
Determine if this is a TRUE EXPLOITABLE SECURITY ISSUE or should be filtered out.

## Criticism Level: {HIGH/MEDIUM/LOW}
HIGH: Assume NOT exploitable unless you can prove both reachability AND attacker control
MEDIUM: Accept strong evidence for one dimension, require proof for the other
LOW: Trust the initial classification unless clearly wrong

## Finding Summary
- Title: {title}
- Type: {vulnerability_type}
- File: {file_path}:{line_start}
- Disposition: {disposition}
- Classification Confidence: {confidence}%

## Initial Classification Checklist
- Source Controlled Input: {status} - {reason}
- Sink Present: {status} - {reason}
- Dataflow Evidenced: {status} - {reason}
- Reachable: {status} - {reason}
- Boundary Crossed: {status} - {reason}
- Not Only Misconfig: {status} - {reason}

## Your Investigation Tasks

**Task 1: Validate Attacker Control**
Question: Can an attacker ACTUALLY control the input to the dangerous sink?
- Use Grep to find all call sites of the vulnerable function
- Use Read to examine the data sources
- Trace back to untrusted boundaries (HTTP, file upload, repo checkout, etc.)
- HIGH CRITICISM: Reject if no clear path from untrusted source to sink

**Task 2: Validate Reachability**
Question: Is this code path ACTUALLY reachable in production?
- Use Grep to find route registrations, entry points, or invocations
- Use Read to check if code is conditionally disabled (feature flags, env checks)
- Verify the function is actually called, not just defined
- HIGH CRITICISM: Reject if no clear invocation path

**Task 3: Differentiate Security vs Bug vs Expected Behavior**
- Security issue: Exploitable by attacker with realistic capabilities
- Bug: Functional problem without security impact
- Hardening: Dangerous pattern but not proven exploitable
- By design: Intentional behavior (e.g., eval() in template engine)
- Expected behavior: Working as designed without risk

## Tools Available
- Read(file_path): Read source files
- Grep(pattern, glob): Search codebase for patterns
- Glob(pattern): Find files by name pattern

## Response Format
Respond with exactly:
```
DECISION: VALID | INVALID
CATEGORY: security_issue | bug | hardening | by_design | expected_behavior
REASONING:
- [Bullet 1: key finding from investigation]
- [Bullet 2: evidence for/against exploitability]
- [Bullet 3: final determination]
```

Be highly skeptical. Default to INVALID unless you can prove it's exploitable.
```

**Key Prompt Elements:**
- Criticism level explicitly stated
- Tasks guide investigation methodology
- Tool usage examples provided
- High skepticism emphasized ("assume NOT exploitable")
- Clear output format for parsing

### 3. Pre-Validation Gates

**Location:** `/backend/services/validation/pre_validation_gates.py`

**Class: `PreValidationGates`**

**Purpose:** Run fast rule-based checks BEFORE expensive LLM validation to save API costs.

**Extracted from ProtocolEvaluator:**

```python
class PreValidationGates:
    """Fast rule-based gates that run before LLM validator."""

    def check_gates(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        protocol_policy: ProtocolPolicy
    ) -> Optional[ValidationResult]:
        """
        Run pre-validation gates. Returns ValidationResult if should be filtered,
        None if should proceed to LLM validation.
        """

        # Gate 1: Disposition filter
        if classification.disposition not in protocol_policy.min_disposition_to_submit:
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Disposition {classification.disposition.value} below threshold",
                    f"Required: {[d.value for d in protocol_policy.min_disposition_to_submit]}"
                ],
                categories=["filtered_by_disposition"]
            )

        # Gate 2: Checklist quality (minimum PROVEN items)
        proven_count = sum(1 for item in [
            classification.proof_checklist.source_controlled_input,
            classification.proof_checklist.sink_present,
            classification.proof_checklist.dataflow_evidenced,
            classification.proof_checklist.reachable,
            classification.proof_checklist.boundary_crossed,
            classification.proof_checklist.not_only_misconfig,
        ] if item.status == ChecklistStatus.PROVEN and item.value)

        if proven_count < protocol_policy.min_checklist_proven_count:
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Only {proven_count}/{protocol_policy.min_checklist_proven_count} checklist items proven",
                    "Insufficient evidence - filtered before LLM validation"
                ],
                categories=["insufficient_evidence"]
            )

        # Gate 3: Obvious false positives
        # - Social engineering detection
        # - shell=False for command injection
        # - Other category-specific quick checks

        return None  # Passed all gates, proceed to LLM
```

**Kept Gates:**
- Disposition threshold (e.g., must be VALID or BUG)
- Checklist quality (minimum PROVEN count)
- Social engineering detection
- Category-specific quick checks (shell=False for command injection)

**What Gets Validated by LLM:**
- Findings with high disposition (VALID/BUG)
- Sufficient checklist items PROVEN
- No obvious false positive signals
- But still needs verification of reachability + attacker control

### 4. ProductionRelevanceFilter (No Changes)

**Current Implementation:** `/backend/services/finding_filters/filters/production_filter.py`

**Keep unchanged** - Both Stage 1 (production check) AND Stage 2 (quick validation) serve important purposes:
- Stage 1: Filter non-production code (test/build/dev)
- Stage 2: Catch obvious false positives cheaply (examples, test utilities)

This is the **fast, cheap first filter** before expensive agentic validation.

## Pipeline Integration

### Modified `triage_with_protocol` Flow

**File:** `/backend/services/finding_triage_service.py`

```python
async def triage_with_protocol(...):
    # ... initialization ...

    # Initialize validators
    self.pre_validation_gates = PreValidationGates()
    if protocol_policy and protocol_policy.enable_llm_validation:
        self.llm_validator = LLMFindingValidator(
            anthropic_api_key=api_key,
            repo_root=repo_root,
            model=protocol_policy.validation_model or "claude-sonnet-3-5-20241022"
        )

    for idx, finding in enumerate(findings):
        try:
            # Step 0: ProductionRelevanceFilter (UNCHANGED - both stages)
            # Quick LLM filter to catch obvious false positives
            if self.production_filter and protocol_policy:
                is_relevant, filter_reason = await asyncio.to_thread(
                    self.production_filter.is_production_relevant,
                    finding
                )
                if not is_relevant:
                    # Mark as HARDENING and skip (existing logic, lines 308-366)
                    continue

            # Step 1: Evidence gathering (unchanged)
            evidence = await asyncio.to_thread(gatherer.gather, finding)

            # Step 2: Classification (unchanged)
            classification = await asyncio.to_thread(
                classifier.classify,
                finding, evidence, threat_model_profile
            )

            # Step 3: Validation
            if protocol_policy:
                # Step 3a: Pre-validation gates (NEW - fast rule checks)
                gate_result = self.pre_validation_gates.check_gates(
                    finding, evidence, classification, protocol_policy
                )

                if gate_result and not gate_result.is_valid:
                    # Failed gates - filtered without LLM validation
                    validation_result = gate_result
                elif protocol_policy.enable_llm_validation:
                    # Step 3b: Deep LLM Validator (NEW - agentic investigation)
                    validation_result = await self.llm_validator.validate(
                        finding=finding,
                        evidence=evidence,
                        classification=classification,
                        threat_model_profile=threat_model_profile,
                        criticism_level=protocol_policy.validation_criticism_level or "high"
                    )
                else:
                    # LLM validation disabled - auto-approve
                    validation_result = ValidationResult(
                        is_valid=True,
                        reasoning=["LLM validation disabled"],
                        categories=[]
                    )

                # Store validation result (for report filtering toggle)
                finding.validation_result = validation_result

                # Convert to SubmissionResult (for backward compatibility)
                submission_result = self._validation_to_submission_result(
                    validation_result, protocol_policy
                )
                finding.submission_result = submission_result

            # Attach metadata
            triaged_finding = self._attach_triage_metadata(
                finding, classification, batch_id, policy_version
            )
            triaged.append(triaged_finding)

            # Track reportable based on validation
            if finding.validation_result and finding.validation_result.is_valid:
                reportable.append(triaged_finding)
```

**Key Integration Points:**
1. ProductionRelevanceFilter still runs at Step 0 (unchanged)
2. Pre-validation gates run before LLM (saves cost)
3. LLM validator replaces ProtocolEvaluator
4. ValidationResult stored on finding for report toggle
5. SubmissionResult still created for backward compatibility

## Data Structures

### New Models (models/schemas.py)

```python
class ValidationResult(BaseModel):
    """Result from LLM-based finding validation."""
    is_valid: bool
    reasoning: list[str]  # Bullet points explaining decision
    categories: list[str]  # e.g., ["security_issue"], ["hardening", "by_design"]
    investigation_steps: Optional[list[str]] = None  # Tool calls made
    confidence: Optional[int] = None  # 0-100, validator's confidence
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class Finding(BaseModel):
    # ... existing fields ...

    # NEW: Validation result from LLM validator
    validation_result: Optional[ValidationResult] = None

    # EXISTING: Submission result from protocol evaluation (backward compat)
    submission_result: Optional[SubmissionResult] = None
```

### Modified ProtocolPolicy

```python
class ProtocolPolicy(BaseModel):
    # ... existing fields ...

    # NEW: LLM validation settings
    enable_llm_validation: bool = True  # Default enabled, can be disabled
    validation_criticism_level: Literal["high", "medium", "low"] = "high"
    validation_model: Optional[str] = None  # Override model
    validation_timeout_seconds: int = 120  # Per-finding timeout
    validation_fallback_on_error: Literal["invalid", "valid", "skip"] = "invalid"
```

### Frontend Types (frontend/types/protocol.ts)

```typescript
export interface ValidationResult {
  is_valid: boolean;
  reasoning: string[];
  categories: string[];
  investigation_steps?: string[];
  confidence?: number;
  timestamp: string;
}

export interface Finding {
  // ... existing fields ...
  validation_result?: ValidationResult;
  submission_result?: SubmissionResult;
}
```

### Database Migration (Optional)

```sql
-- Add validation_result column to findings table
ALTER TABLE findings ADD COLUMN validation_result JSONB;
CREATE INDEX idx_findings_validation_valid ON findings ((validation_result->>'is_valid'));
```

## Report Toggle Implementation

**Purpose:** Users can toggle between filtered (validated) and unfiltered (all classified) findings.

**Frontend Toggle (FindingsReportView):**

```typescript
const [showFiltered, setShowFiltered] = useState(true);

const displayedFindings = useMemo(() => {
  if (showFiltered) {
    // Show only LLM-validated findings
    return findings.filter(f =>
      f.validation_result?.is_valid === true ||
      !f.validation_result  // Include findings without validation (legacy)
    );
  } else {
    // Show all classified findings
    return findings;
  }
}, [findings, showFiltered]);
```

**UI Toggle Component:**

```tsx
<div className="filter-toggle">
  <label>
    <input
      type="checkbox"
      checked={showFiltered}
      onChange={(e) => setShowFiltered(e.target.checked)}
    />
    Show only validated findings
  </label>
  <span className="count">
    {showFiltered
      ? `${displayedFindings.length} validated`
      : `${displayedFindings.length} total (${findings.length - displayedFindings.length} filtered)`
    }
  </span>
</div>
```

**Finding Badge Display:**

```tsx
{finding.validation_result && (
  <span className={`validation-badge ${finding.validation_result.is_valid ? 'valid' : 'invalid'}`}>
    {finding.validation_result.is_valid ? '✓ Validated' : '✗ Filtered'}
  </span>
)}
```

**Key Points:**
- Toggle is per-session (localStorage)
- Default: filtered view (validated only)
- Unfiltered view shows validation reasoning for transparency
- Backward compatible: findings without validation_result treated as validated

## Error Handling and Timeouts

**Problem:** Agentic LLM validator can fail or run too long, blocking the triage pipeline.

**Solution: Graceful Degradation**

```python
class LLMFindingValidator:
    async def validate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str,
        timeout_seconds: int = 120
    ) -> ValidationResult:
        """Validate finding with timeout."""
        try:
            # Run validation with timeout
            result = await asyncio.wait_for(
                self._run_validation(...),
                timeout=timeout_seconds
            )
            return result

        except asyncio.TimeoutError:
            # Timeout: default to INVALID (conservative)
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Validation timeout after {timeout_seconds}s",
                    "Insufficient time to prove exploitability - filtered conservatively"
                ],
                categories=["timeout"],
                confidence=0
            )

        except Exception as e:
            # Error: log and default to INVALID (conservative)
            logger.error(f"LLM validation error for {finding.id}: {e}")
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Validation error: {str(e)[:200]}",
                    "Could not complete investigation - filtered conservatively"
                ],
                categories=["error"],
                confidence=0
            )
```

**Fallback Behavior:**

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Timeout | Mark as INVALID | Conservative: can't prove exploitability in time |
| API Error | Mark as INVALID | Conservative: incomplete investigation |
| Tool Error | Continue validation | Best effort: validator can work around tool failures |
| Parse Error | Mark as INVALID | Conservative: can't interpret validator output |

**Configurable Behavior (ProtocolPolicy):**
```python
validation_fallback_on_error: Literal["invalid", "valid", "skip"] = "invalid"
# invalid = filter on error (conservative, default)
# valid = approve on error (aggressive)
# skip = don't validate, use classification (bypass)
```

**Key Principles:**
- **Conservative defaults** - When in doubt, filter out
- **Never block pipeline** - Timeouts and errors don't crash triage
- **Transparency** - Reasoning explains why validation failed
- **User control** - Configurable fallback behavior per protocol

## Testing Strategy

### 1. Unit Tests

```python
# tests/services/validation/test_llm_validator.py

def test_llm_validator_timeout():
    """Test validator handles timeout gracefully."""
    validator = LLMFindingValidator(api_key="test", repo_root="/tmp")
    result = await validator.validate(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        criticism_level="high",
        timeout_seconds=1  # Force timeout
    )
    assert result.is_valid == False
    assert "timeout" in result.categories

def test_llm_validator_tool_execution():
    """Test validator executes tools correctly."""
    # Mock Anthropic API to return tool_use response
    # Verify tools are called with correct params
    # Verify tool results are passed back correctly

def test_criticism_levels():
    """Test different criticism levels produce different behavior."""
    # Mock same finding with high/medium/low criticism
    # Verify high criticism is more conservative
```

### 2. Integration Tests

```python
# tests/integration/test_llm_validation_pipeline.py

async def test_full_pipeline_with_llm_validation():
    """Test complete triage pipeline with LLM validation enabled."""
    # Given: findings, protocol policy with enable_llm_validation=True
    # When: run triage_with_protocol
    # Then:
    #   - ProductionRelevanceFilter runs first
    #   - Classification happens
    #   - Pre-validation gates run
    #   - LLM validator runs for passing findings
    #   - validation_result populated
    #   - reportable only includes validated findings

async def test_pipeline_with_validation_disabled():
    """Test pipeline bypasses LLM validation when disabled."""
    # Given: protocol policy with enable_llm_validation=False
    # When: run triage_with_protocol
    # Then: all classified findings auto-approved (no validation_result)
```

### 3. Manual Testing Scenarios

| Scenario | Expected Behavior |
|----------|-------------------|
| **Obvious FP (exec in test)** | ProductionRelevanceFilter filters at Step 0 |
| **exec() not reachable** | LLM validator investigates, marks INVALID |
| **exec() with user input** | LLM validator traces dataflow, marks VALID |
| **Validation timeout** | Finding marked INVALID with timeout category |
| **API key missing** | Validation skipped, auto-approve or error based on config |
| **Toggle filtered view** | UI shows only validated findings |
| **Toggle unfiltered view** | UI shows all findings with validation badges |

### 4. Performance Testing

```python
async def test_validation_performance():
    """Test validation doesn't block pipeline excessively."""
    findings = [generate_mock_finding() for _ in range(50)]

    start = time.time()
    result = await triage_service.triage_with_protocol(
        repo_root="/test",
        findings=findings,
        protocol_policy=default_policy
    )
    elapsed = time.time() - start

    # With 50 findings, 120s timeout each, max 100 minutes
    # But pre-validation gates should filter most quickly
    assert elapsed < 600  # 10 minutes max
```

**Key Testing Principles:**
- **Mock Anthropic API** for unit tests (don't call real API)
- **Test error paths** thoroughly (timeouts, API errors, parse errors)
- **Manual validation** on real repos with known vulnerabilities
- **Cost monitoring** during testing (LLM calls add up quickly)

## Implementation Considerations

### Cost Management

**API Cost Estimation:**
- ProductionRelevanceFilter: ~$0.01 per finding (fast, 300 tokens)
- LLM Validator: ~$0.10-0.50 per finding (agentic, 4-10 tool calls, 10K+ tokens)
- For 100 findings: $10-50 per scan with validation enabled
- Pre-validation gates critical to reduce validated count

**Cost Optimization Strategies:**
- Pre-validation gates filter 60-80% of findings before LLM
- Criticism level "medium" or "low" for faster validation (fewer tool calls)
- Batch similar findings (future enhancement)
- Cache validation results by finding fingerprint (future enhancement)

### Performance Considerations

**Parallelization:**
- Current pipeline is sequential per-finding
- Could parallelize validation across findings (future enhancement)
- Limit concurrent LLM calls to avoid rate limits (e.g., 5 concurrent)

**Timeout Tuning:**
- Default 120s per finding may be too long for large batches
- Consider adaptive timeout: 60s for high-volume batches
- Trade-off: thoroughness vs. speed

### Migration Path

**Phase 1: Add LLM Validator (disabled by default)**
- Implement LLMFindingValidator
- Add validation_result to Finding schema
- Wire into pipeline with enable_llm_validation=False by default
- Test thoroughly on known repositories

**Phase 2: Enable for Testing (opt-in)**
- Document configuration for enabling LLM validation
- Collect feedback on false positive rate
- Tune criticism level and prompt based on results
- Monitor costs

**Phase 3: Enable by Default (production)**
- Switch enable_llm_validation=True by default
- Provide clear documentation on disabling if needed
- Add cost tracking dashboard

**Phase 4: Optimize (future enhancements)**
- Parallel validation
- Result caching
- Batch processing
- Custom validation prompts per vulnerability type

### Backward Compatibility

- Existing scans without validation_result: treated as validated (permissive)
- Frontend toggle: gracefully handles missing validation_result
- SubmissionResult still populated for existing UI components
- Can disable validation entirely (enable_llm_validation=False) to revert behavior

### Documentation Requirements

1. **User Guide**: How to enable/disable/configure LLM validation
2. **Cost Guide**: Expected API costs, optimization tips
3. **Prompt Engineering Guide**: How to customize validation prompts
4. **Troubleshooting**: Common issues (timeouts, API errors, high costs)

## Diagramming System Compatibility

**The diagramming system is NOT affected by this change.**

The flow visualization displays:
- Investigation flow nodes and edges from FlowService
- Triage gateway node showing metrics (reportable count, filtered count)
- Finding nodes with disposition metadata

**What the diagram needs (unchanged):**
1. TriageResult with metrics (counts, dispositions)
2. triage_gateway flow node creation
3. Findings with disposition metadata

**What changes (doesn't affect diagram):**
- ProtocolEvaluator replaced by LLM validator
- ValidationResult added to findings
- SubmissionResult still created for backward compatibility

The new validator produces the same output structure (TriageResult), so the diagram continues to work without modifications.

## Files to Create/Modify

### New Files

1. `/backend/services/validation/llm_validator.py` - LLMFindingValidator class
2. `/backend/services/validation/pre_validation_gates.py` - PreValidationGates class
3. `/backend/services/validation/__init__.py` - Module exports
4. `/backend/tests/services/validation/test_llm_validator.py` - Unit tests
5. `/backend/tests/integration/test_llm_validation_pipeline.py` - Integration tests

### Modified Files

1. `/backend/services/finding_triage_service.py` - Wire in LLM validator
2. `/backend/models/schemas.py` - Add ValidationResult, update Finding and ProtocolPolicy
3. `/frontend/types/protocol.ts` - Add ValidationResult type
4. `/frontend/components/FindingsReportView.tsx` - Add filter toggle
5. `/frontend/components/FindingDrawer/SubmissionPanel.tsx` - Display validation result

### Unchanged Files

1. `/backend/services/finding_filters/filters/production_filter.py` - Keep as-is (both stages)
2. `/backend/services/classification/classifier.py` - No changes
3. `/backend/services/evidence/gatherer.py` - No changes
4. `/backend/services/flow_service.py` - No changes (triage_gateway node unchanged)
5. `/frontend/components/FlowVisualization/FlowVisualization.tsx` - No changes

## Summary

This design adds a sophisticated secondary validation layer to the triage system that uses agentic LLM investigation to deeply validate findings. By keeping ProductionRelevanceFilter as a fast first filter and adding pre-validation gates, we minimize API costs while maximizing accuracy. The system is configurable, backward compatible, and provides clear transparency through the report toggle feature.

**Key Benefits:**
- Significantly reduce false positives
- Deep validation of reachability and attacker control
- Configurable criticism level
- Optional (can be disabled)
- Transparent (report shows filtered vs validated)
- Cost-optimized (two-tier filtering)
- Backward compatible

**Next Steps:**
1. Review and approve design
2. Create implementation plan with task breakdown
3. Implement Phase 1 (validator disabled by default)
4. Test on known repositories
5. Gradually enable and tune
