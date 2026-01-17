# VRP Strictness Improvements Design

> **Context:** This design addresses false positive reduction in the vulnerability triage system by implementing strict VRP (Vulnerability Research Program) acceptance criteria.

**Goal:** Reduce noise in VRP findings by implementing strict filtering for non-production code, enforcing evidence requirements per vulnerability type, and providing clear policy-driven triage decisions.

**Architecture:** Three-layer approach separating concerns:
1. **Pre-triage filtering** - Remove findings from excluded paths before evidence gathering
2. **StrictClassifier** - Evaluate technical proof checklist (unchanged)
3. **PolicyEvaluator** - Apply VRP acceptance criteria and output classification

**Tech Stack:** Python dataclasses, Pydantic models, existing triage service integration

---

## Problem Statement

**Current Issues:**

1. **Origination regression**: Findings originate from `test/`, `tools/`, `third_party/` despite exclusion rules
   - Example: `third_party/dawn/tools/fetch_dawn_dependencies.py`
   - Example: `test/renderdiff/src/golden_manager.py`
   - Example: `tools/zbloat/zbloat.py`

2. **Command injection over-reporting**: System doesn't distinguish between:
   - Shell injection with `shell=True` (VALID for VRP)
   - Argument injection without shell parsing (HARDENING, not VRP-reportable)

3. **Integer overflow noise**: Reports speculative overflows without:
   - Proven attacker control over operands
   - Evidence of allocation/bounds mismatch
   - Reachable dangerous use

4. **No deduplication**: Scanners emit duplicates, cluttering findings list

5. **Mixed concerns**: Threat model (attacker capabilities) conflated with triage policy (program bureaucracy)

**Success Criteria:**

- Zero findings from `test/`, `tools/`, `third_party/`, `scripts/`, `examples/`, `ci/`, `docs/`, `migrations/` in VRP mode
- Command injection marked VALID only with `shell=True` + string interpolation + boundary crossing
- Integer overflow requires proven allocation mismatch to be VALID
- Duplicates eliminated at ingestion
- Clear separation: ThreatModelProfile (attacker model) vs TriagePolicy (VRP acceptance)

---

## Design: Architecture Overview

### Three-Layer Pipeline

```
Findings Ingestion
    ↓
[1. Pre-Triage Filter] ← TriagePolicy.path_classification
    ↓ (filtered findings)
Evidence Gathering (EvidenceGatherer)
    ↓ (evidence)
Classification (StrictClassifier)
    ↓ (disposition + checklist)
[2. Policy Evaluator] ← TriagePolicy.evidence_gates
    ↓ (policy decision)
Output (REPORT_VRP / REPORT_LOW / HARDENING / DO_NOT_REPORT)
```

### Component Responsibilities

**Pre-Triage Filter:**
- Input: Raw findings + TriagePolicy
- Classify file paths: runtime / tooling / third_party
- Filter based on policy rules (e.g., exclude third_party entirely)
- Output: Filtered findings for triage

**StrictClassifier (unchanged):**
- Input: Finding + Evidence
- Evaluate proof checklist (A-F items)
- Apply disposition rules
- Output: ClassificationResult with disposition

**PolicyEvaluator (new):**
- Input: Finding + Evidence + ClassificationResult + TriagePolicy
- Evaluate evidence gates per vulnerability type
- Apply path-based overrides (tooling findings need stronger boundary)
- Output: PolicyDecision (REPORT_VRP / REPORT_LOW / HARDENING / DO_NOT_REPORT)

---

## Design: Data Models

### TriagePolicy

```python
from enum import Enum
from pydantic import BaseModel, Field

class PathClassification(str, Enum):
    runtime = "runtime"          # Production code
    tooling = "tooling"          # Developer tools, may run on CI
    third_party = "third_party"  # Vendored dependencies
    unknown = "unknown"

class PolicyDecision(str, Enum):
    REPORT_SECURITY_VRP = "report_security_vrp"           # High confidence, VRP-reportable
    REPORT_SECURITY_LOW_CONFIDENCE = "report_security_low" # Valid but needs review
    HARDENING_ONLY = "hardening_only"                     # Not security issue, hardening opp
    DO_NOT_REPORT = "do_not_report"                       # Filtered out

class PathClassificationConfig(BaseModel):
    """Path classification rules for scope filtering."""
    runtime_roots: list[str] = Field(
        default_factory=lambda: ["src/", "app/", "backend/", "frontend/", "lib/", "libs/"]
    )
    tooling_roots: list[str] = Field(
        default_factory=lambda: ["tools/", "scripts/", "examples/", "samples/"]
    )
    third_party_roots: list[str] = Field(
        default_factory=lambda: [
            "third_party/", "vendor/", "node_modules/",
            ".venv/", "site-packages/", "dist/", "build/",
            "target/", "out/"
        ]
    )
    test_roots: list[str] = Field(
        default_factory=lambda: ["test/", "tests/", "__tests__/"]
    )
    ci_roots: list[str] = Field(
        default_factory=lambda: [".github/", ".gitlab/", "ci/"]
    )
    docs_roots: list[str] = Field(
        default_factory=lambda: ["docs/", "documentation/"]
    )
    migration_roots: list[str] = Field(
        default_factory=lambda: ["migrations/", "migrate/"]
    )

class CommandInjectionGate(BaseModel):
    """Evidence requirements for command injection to be VRP-reportable."""
    require_shell_execution: bool = True  # shell=True or os.system
    require_attacker_controls_shell_string: bool = True  # Not just arguments
    credible_boundaries: list[str] = Field(
        default_factory=lambda: ["network", "ci_artifact", "repo_checkout", "file_input"]
    )

class IntegerOverflowGate(BaseModel):
    """Evidence requirements for integer overflow to be VRP-reportable."""
    require_attacker_controlled_operands: bool = True
    require_overflow_prone_operation: bool = True  # Multiplication or unchecked addition
    require_allocation_or_bounds_use: bool = True  # malloc, array index, buffer size
    require_proven_mismatch: bool = True  # 32-bit calc → 64-bit size, etc.

class MemoryCorruptionGate(BaseModel):
    """Evidence requirements for memory corruption to be VRP-reportable."""
    require_asan_trace: bool = False  # Prefer but don't require
    require_release_config: bool = True  # Must trigger in NDEBUG/release
    require_untrusted_input_path: bool = True

class DosGate(BaseModel):
    """Evidence requirements for DoS to be VRP-reportable."""
    require_service_boundary: bool = True  # Network service, not local script

class EvidenceGates(BaseModel):
    """Per-vulnerability-type evidence requirements."""
    command_injection: CommandInjectionGate = Field(default_factory=CommandInjectionGate)
    integer_overflow: IntegerOverflowGate = Field(default_factory=IntegerOverflowGate)
    memory_corruption: MemoryCorruptionGate = Field(default_factory=MemoryCorruptionGate)
    dos: DosGate = Field(default_factory=DosGate)

class DeduplicationConfig(BaseModel):
    """Deduplication strategy configuration."""
    enabled: bool = True
    strategy: str = "exact"  # "exact" | "fuzzy" | "symbol"
    exact_match_fields: list[str] = Field(
        default_factory=lambda: ["file_path", "line_start", "vulnerability_type", "title"]
    )

class TriagePolicy(BaseModel):
    """
    VRP triage policy configuration.

    Encodes "what do we bother reporting given strictness, scope, and evidence?"
    Separate from ThreatModelProfile (attacker capabilities).
    """
    name: str  # e.g., "vrp-google-oss-strict", "internal-audit"

    # Path classification and filtering
    path_classification: PathClassificationConfig = Field(
        default_factory=PathClassificationConfig
    )
    filter_third_party: bool = True  # Drop findings from third_party_roots
    filter_tests: bool = True  # Drop findings from test_roots
    filter_ci: bool = True  # Drop findings from ci_roots
    filter_docs: bool = True  # Drop findings from docs_roots
    filter_migrations: bool = True  # Drop findings from migration_roots

    # Tooling findings require stronger boundary (not auto-filtered)
    tooling_requires_ci_boundary: bool = True

    # Evidence gates per vulnerability type
    evidence_gates: EvidenceGates = Field(default_factory=EvidenceGates)

    # Deduplication
    deduplication: DeduplicationConfig = Field(default_factory=DeduplicationConfig)

    # Disposition overrides
    report_hardening: bool = False  # Default: don't report HARDENING findings
    report_by_design: bool = False  # Default: don't report BY_DESIGN findings
```

### PolicyEvaluationResult

```python
class PolicyEvaluationResult(BaseModel):
    """Result from policy evaluation."""
    decision: PolicyDecision
    path_classification: PathClassification
    gate_results: dict[str, bool]  # Which gates passed/failed
    reasoning: list[str]  # Why this decision was made
    original_disposition: Disposition  # From StrictClassifier
    overridden: bool  # True if policy changed the classification
```

---

## Design: Pre-Triage Filter

### Purpose
Remove noise before expensive evidence gathering and classification.

### Logic

```python
def classify_path(file_path: str, config: PathClassificationConfig) -> PathClassification:
    """Classify file path into runtime/tooling/third_party/unknown."""
    # Normalize path to repo-relative
    rel_path = normalize_to_repo_relative(file_path)

    # Check in priority order (most specific first)
    if any(rel_path.startswith(root) or f"/{root}" in rel_path
           for root in config.third_party_roots):
        return PathClassification.third_party

    if any(rel_path.startswith(root) or f"/{root}" in rel_path
           for root in config.test_roots):
        return PathClassification.third_party  # Treat tests as excluded

    if any(rel_path.startswith(root) or f"/{root}" in rel_path
           for root in config.ci_roots):
        return PathClassification.third_party  # Treat CI as excluded

    if any(rel_path.startswith(root) or f"/{root}" in rel_path
           for root in config.docs_roots):
        return PathClassification.third_party  # Treat docs as excluded

    if any(rel_path.startswith(root) or f"/{root}" in rel_path
           for root in config.migration_roots):
        return PathClassification.third_party  # Treat migrations as excluded

    if any(rel_path.startswith(root) or f"/{root}" in rel_path
           for root in config.tooling_roots):
        return PathClassification.tooling

    if any(rel_path.startswith(root) for root in config.runtime_roots):
        return PathClassification.runtime

    return PathClassification.unknown

def pre_filter_findings(
    findings: list[Finding],
    policy: TriagePolicy
) -> list[Finding]:
    """Filter findings based on path classification before triage."""
    filtered = []

    for finding in findings:
        path_class = classify_path(finding.file_path, policy.path_classification)

        # Apply filters
        if path_class == PathClassification.third_party and policy.filter_third_party:
            continue  # Skip

        # Attach classification for later use
        finding.path_classification = path_class
        filtered.append(finding)

    return filtered
```

### Integration Point

```python
# In FindingTriageService.triage_findings()
def triage_findings(
    self,
    repo_root: str,
    findings: list[Finding],
    policy: Optional[TriagePolicy] = None,
    threat_model_profile: Optional[dict] = None,
) -> TriageResult:
    # NEW: Pre-filter findings
    if policy:
        findings = pre_filter_findings(findings, policy)

    # Existing triage logic...
    for finding in findings:
        evidence = gatherer.gather(finding)
        classification = classifier.classify(finding, evidence, threat_model_profile)

        # NEW: Policy evaluation
        if policy:
            policy_result = policy_evaluator.evaluate(
                finding, evidence, classification, policy
            )
            finding.policy_decision = policy_result.decision
            finding.policy_reasoning = policy_result.reasoning

        triaged.append(finding)

    return TriageResult(...)
```

---

## Design: PolicyEvaluator Service

### Purpose
Apply VRP acceptance criteria after classification to determine reportability.

### Core Logic

```python
class PolicyEvaluator:
    """
    Evaluate findings against TriagePolicy.

    Runs after StrictClassifier to apply VRP-specific gates and overrides.
    """

    def evaluate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        policy: TriagePolicy
    ) -> PolicyEvaluationResult:
        """
        Evaluate finding against policy.

        Returns PolicyDecision: REPORT_VRP / REPORT_LOW / HARDENING / DO_NOT_REPORT
        """
        gate_results = {}
        reasoning = []

        # Get path classification (from pre-filter)
        path_class = getattr(finding, 'path_classification', PathClassification.unknown)

        # Step 1: Check if tooling finding needs stronger boundary
        if path_class == PathClassification.tooling:
            if policy.tooling_requires_ci_boundary:
                if not self._has_ci_boundary(evidence):
                    return PolicyEvaluationResult(
                        decision=PolicyDecision.DO_NOT_REPORT,
                        path_classification=path_class,
                        gate_results={"tooling_ci_boundary": False},
                        reasoning=["Tooling finding requires CI/automated boundary for VRP"],
                        original_disposition=classification.disposition,
                        overridden=True
                    )

        # Step 2: Apply evidence gates per vulnerability type
        category = classification.category

        if category == VulnerabilityCategory.COMMAND_INJECTION:
            gate_passed, gate_reason = self._evaluate_command_injection_gate(
                finding, evidence, classification, policy.evidence_gates.command_injection
            )
            gate_results["command_injection"] = gate_passed
            reasoning.append(gate_reason)

            if not gate_passed:
                return PolicyEvaluationResult(
                    decision=PolicyDecision.HARDENING_ONLY,
                    path_classification=path_class,
                    gate_results=gate_results,
                    reasoning=reasoning,
                    original_disposition=classification.disposition,
                    overridden=True
                )

        elif category == VulnerabilityCategory.INTEGER_OVERFLOW:
            gate_passed, gate_reason = self._evaluate_integer_overflow_gate(
                finding, evidence, classification, policy.evidence_gates.integer_overflow
            )
            gate_results["integer_overflow"] = gate_passed
            reasoning.append(gate_reason)

            if not gate_passed:
                return PolicyEvaluationResult(
                    decision=PolicyDecision.HARDENING_ONLY,
                    path_classification=path_class,
                    gate_results=gate_results,
                    reasoning=reasoning,
                    original_disposition=classification.disposition,
                    overridden=True
                )

        # Step 3: Map disposition to policy decision
        decision = self._map_disposition_to_decision(
            classification.disposition, policy, gate_results
        )

        return PolicyEvaluationResult(
            decision=decision,
            path_classification=path_class,
            gate_results=gate_results,
            reasoning=reasoning or ["Classification matches policy criteria"],
            original_disposition=classification.disposition,
            overridden=False
        )

    def _evaluate_command_injection_gate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        gate: CommandInjectionGate
    ) -> tuple[bool, str]:
        """
        Check if command injection meets VRP evidence requirements.

        Returns (passed, reason)
        """
        # Requirement 1: shell=True or os.system (shell execution)
        if gate.require_shell_execution:
            has_shell = self._has_shell_execution(evidence)
            if not has_shell:
                return (False, "Command injection gate failed: no shell=True or os.system")

        # Requirement 2: Attacker controls shell string (not just arguments)
        if gate.require_attacker_controls_shell_string:
            controls_string = self._attacker_controls_shell_string(evidence, classification)
            if not controls_string:
                return (False, "Command injection gate failed: no string interpolation, only argument injection")

        # Requirement 3: Credible boundary (network, CI, file input)
        if gate.credible_boundaries:
            boundary = evidence.input_channel.value if evidence.input_channel else None
            if boundary not in gate.credible_boundaries:
                return (False, f"Command injection gate failed: boundary={boundary} not in {gate.credible_boundaries}")

        return (True, "Command injection gate passed: shell=True + string interpolation + credible boundary")

    def _has_shell_execution(self, evidence: Evidence) -> bool:
        """Check if code uses shell=True or os.system."""
        snippet = evidence.snippet or ""

        # Check for explicit shell=True
        if re.search(r'shell\s*=\s*True', snippet):
            return True

        # Check for os.system, os.popen (implicit shell)
        if re.search(r'os\.(system|popen)\s*\(', snippet):
            return True

        return False

    def _attacker_controls_shell_string(
        self, evidence: Evidence, classification: ClassificationResult
    ) -> bool:
        """Check if attacker controls the command string (not just arguments)."""
        snippet = evidence.snippet or ""

        # Look for string interpolation patterns
        # f-string: f"command {user_input}"
        if re.search(r'f["\'].*?\{.*?\}.*?["\']', snippet):
            # Check if this f-string is passed to subprocess/os.system
            if 'subprocess' in snippet or 'os.system' in snippet:
                return True

        # String concatenation: "command " + user_input
        if re.search(r'["\'].*?["\'].*?\+.*?\w+', snippet) or re.search(r'\w+.*?\+.*?["\']', snippet):
            if 'subprocess' in snippet or 'os.system' in snippet:
                return True

        # .format(): "command {}".format(user_input)
        if re.search(r'["\'].*?\{.*?\}.*?["\']\.format\(', snippet):
            if 'subprocess' in snippet or 'os.system' in snippet:
                return True

        # Check checklist: if dataflow_evidenced is PROVEN with unsafe pattern
        if classification.proof_checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN:
            reason = classification.proof_checklist.dataflow_evidenced.reason or ""
            if "string interpolation" in reason.lower() or "concatenation" in reason.lower():
                return True

        return False

    def _evaluate_integer_overflow_gate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        gate: IntegerOverflowGate
    ) -> tuple[bool, str]:
        """
        Check if integer overflow meets VRP evidence requirements.

        Strict: requires proven allocation mismatch + attacker control + dangerous use.

        Returns (passed, reason)
        """
        missing = []

        # Requirement 1: Attacker-controlled operands
        if gate.require_attacker_controlled_operands:
            if classification.proof_checklist.source_controlled_input.status != ChecklistStatus.PROVEN:
                missing.append("no proven attacker control over operands")

        # Requirement 2: Overflow-prone operation (multiplication or unchecked addition)
        if gate.require_overflow_prone_operation:
            has_overflow_op = self._has_overflow_prone_operation(evidence)
            if not has_overflow_op:
                missing.append("no overflow-prone operation (multiplication/unchecked addition)")

        # Requirement 3: Allocation or bounds check using result
        if gate.require_allocation_or_bounds_use:
            has_dangerous_use = self._has_allocation_or_bounds_use(evidence)
            if not has_dangerous_use:
                missing.append("no allocation/bounds use detected")

        # Requirement 4: Proven mismatch (32-bit calc → 64-bit size, etc.)
        if gate.require_proven_mismatch:
            has_mismatch = self._has_proven_type_mismatch(evidence)
            if not has_mismatch:
                missing.append("no proven type mismatch (32-bit → 64-bit, etc.)")

        if missing:
            return (False, f"Integer overflow gate failed: {'; '.join(missing)}")

        return (True, "Integer overflow gate passed: attacker control + overflow op + allocation use + mismatch")

    def _has_overflow_prone_operation(self, evidence: Evidence) -> bool:
        """Check for multiplication or unchecked addition."""
        snippet = evidence.snippet or ""

        # Look for multiplication
        if re.search(r'\w+\s*\*\s*\w+', snippet):
            return True

        # Look for addition without overflow check
        # (Hard to prove "unchecked" statically, so look for addition near allocation)
        if re.search(r'\w+\s*\+\s*\w+', snippet):
            if 'malloc' in snippet or 'calloc' in snippet or 'new ' in snippet:
                return True

        return False

    def _has_allocation_or_bounds_use(self, evidence: Evidence) -> bool:
        """Check if result is used in allocation or bounds check."""
        snippet = evidence.snippet or ""

        # Memory allocation
        if any(func in snippet for func in ['malloc', 'calloc', 'realloc', 'new ', 'new[']):
            return True

        # Array indexing
        if re.search(r'\w+\[.*?\]', snippet):
            return True

        # Buffer size parameter
        if any(func in snippet for func in ['memcpy', 'strcpy', 'strncpy', 'read', 'write']):
            return True

        return False

    def _has_proven_type_mismatch(self, evidence: Evidence) -> bool:
        """Check for type mismatch (32-bit calc → 64-bit use)."""
        snippet = evidence.snippet or ""

        # Look for int32 → size_t cast
        if re.search(r'\(size_t\).*?\(int32|int\)', snippet):
            return True

        # Look for int multiplication assigned to size_t
        if re.search(r'size_t\s+\w+\s*=.*?\*', snippet):
            return True

        # This is hard to prove statically - may need type inference
        # For MVP, be conservative and assume mismatch if we see multiplication + allocation
        if self._has_overflow_prone_operation(evidence) and self._has_allocation_or_bounds_use(evidence):
            return True

        return False

    def _has_ci_boundary(self, evidence: Evidence) -> bool:
        """Check if finding crosses CI/automated boundary."""
        if evidence.input_channel in [InputChannel.ci_artifact, InputChannel.repo_checkout]:
            return True

        # Check for CI-related signals
        if hasattr(evidence, 'input_channel_signals'):
            ci_signals = ['ci_artifact', 'automated_pipeline', 'repo_checkout']
            if any(sig in evidence.input_channel_signals for sig in ci_signals):
                return True

        return False

    def _map_disposition_to_decision(
        self,
        disposition: Disposition,
        policy: TriagePolicy,
        gate_results: dict[str, bool]
    ) -> PolicyDecision:
        """Map StrictClassifier disposition to PolicyDecision."""
        # VALID → REPORT_VRP (high confidence)
        if disposition == Disposition.VALID_SECURITY_ISSUE:
            return PolicyDecision.REPORT_SECURITY_VRP

        # BUG → REPORT_LOW (valid but lower confidence)
        if disposition == Disposition.BUG:
            return PolicyDecision.REPORT_SECURITY_LOW_CONFIDENCE

        # HARDENING → check policy
        if disposition == Disposition.HARDENING:
            if policy.report_hardening:
                return PolicyDecision.HARDENING_ONLY
            return PolicyDecision.DO_NOT_REPORT

        # BY_DESIGN → check policy
        if disposition == Disposition.BY_DESIGN:
            if policy.report_by_design:
                return PolicyDecision.HARDENING_ONLY
            return PolicyDecision.DO_NOT_REPORT

        # SPECULATIVE, MISCONFIGURATION → DO_NOT_REPORT
        return PolicyDecision.DO_NOT_REPORT
```

---

## Design: Deduplication

### Strategy: Exact Match

Deduplicate findings based on exact field matching before triage.

### Implementation

```python
def deduplicate_findings(
    findings: list[Finding],
    config: DeduplicationConfig
) -> list[Finding]:
    """
    Remove duplicate findings based on configured strategy.

    For "exact" strategy: match on file_path + line_start + vulnerability_type + title
    """
    if not config.enabled:
        return findings

    if config.strategy != "exact":
        raise NotImplementedError(f"Dedup strategy {config.strategy} not implemented")

    seen = set()
    deduplicated = []

    for finding in findings:
        # Build fingerprint from configured fields
        fingerprint_parts = []
        for field in config.exact_match_fields:
            value = getattr(finding, field, None)
            if value is not None:
                fingerprint_parts.append(str(value))

        fingerprint = "|".join(fingerprint_parts)

        if fingerprint not in seen:
            seen.add(fingerprint)
            deduplicated.append(finding)

    return deduplicated
```

### Integration Point

```python
# In FindingTriageService.triage_findings()
def triage_findings(
    self,
    repo_root: str,
    findings: list[Finding],
    policy: Optional[TriagePolicy] = None,
    threat_model_profile: Optional[dict] = None,
) -> TriageResult:
    # Step 1: Deduplicate
    if policy and policy.deduplication.enabled:
        findings = deduplicate_findings(findings, policy.deduplication)

    # Step 2: Pre-filter
    if policy:
        findings = pre_filter_findings(findings, policy)

    # Step 3: Triage (existing logic)
    # ...
```

---

## Design: Default VRP Policy

### vrp-google-oss-strict

```python
VRP_GOOGLE_OSS_STRICT = TriagePolicy(
    name="vrp-google-oss-strict",

    # Path filtering: exclude test/tools/third_party/ci/docs/migrations
    path_classification=PathClassificationConfig(
        runtime_roots=["src/", "app/", "backend/", "frontend/", "lib/", "libs/", "filament/", "gltfio/"],
        tooling_roots=["tools/", "scripts/", "examples/", "samples/"],
        third_party_roots=["third_party/", "vendor/", "node_modules/", ".venv/", "site-packages/"],
        test_roots=["test/", "tests/", "__tests__/"],
        ci_roots=[".github/", ".gitlab/", "ci/"],
        docs_roots=["docs/", "documentation/"],
        migration_roots=["migrations/", "migrate/"]
    ),
    filter_third_party=True,
    filter_tests=True,
    filter_ci=True,
    filter_docs=True,
    filter_migrations=True,
    tooling_requires_ci_boundary=True,  # Tooling findings need CI/automated boundary

    # Evidence gates
    evidence_gates=EvidenceGates(
        command_injection=CommandInjectionGate(
            require_shell_execution=True,
            require_attacker_controls_shell_string=True,
            credible_boundaries=["network", "ci_artifact", "repo_checkout", "file_input"]
        ),
        integer_overflow=IntegerOverflowGate(
            require_attacker_controlled_operands=True,
            require_overflow_prone_operation=True,
            require_allocation_or_bounds_use=True,
            require_proven_mismatch=True
        ),
        memory_corruption=MemoryCorruptionGate(
            require_asan_trace=False,  # Prefer but don't require
            require_release_config=True,
            require_untrusted_input_path=True
        ),
        dos=DosGate(
            require_service_boundary=True
        )
    ),

    # Deduplication
    deduplication=DeduplicationConfig(
        enabled=True,
        strategy="exact",
        exact_match_fields=["file_path", "line_start", "vulnerability_type", "title"]
    ),

    # Output filtering
    report_hardening=False,
    report_by_design=False
)
```

---

## Design: API Integration

### FindingTriageService Changes

```python
class FindingTriageService:
    def __init__(self):
        self.quest_orchestrator: Optional[EvidenceQuestOrchestrator] = None
        self.protocol_evaluator = ProtocolEvaluator()
        self.policy_evaluator = PolicyEvaluator()  # NEW

    def triage_findings(
        self,
        repo_root: str,
        findings: list[Finding],
        policy: Optional[TriagePolicy] = None,  # NEW
        policy_version: str = "1.0.0",
        budgets: Optional[BudgetConfig] = None,
        threat_model_profile: Optional[dict] = None,
    ) -> TriageResult:
        """
        Triage findings with optional policy evaluation.

        Pipeline:
        1. Deduplicate (if policy.deduplication.enabled)
        2. Pre-filter by path (if policy provided)
        3. Gather evidence
        4. Classify
        5. Evaluate policy (if policy provided)
        """
        if not findings:
            return TriageResult(...)

        batch_id = self._generate_batch_id()

        # Step 1: Deduplicate
        if policy and policy.deduplication.enabled:
            findings = deduplicate_findings(findings, policy.deduplication)

        # Step 2: Pre-filter
        if policy:
            findings = pre_filter_findings(findings, policy)

        if not findings:
            # All filtered out
            return TriageResult(
                triaged_findings=[],
                reportable_findings=[],
                metrics=TriageMetrics(...),
                batch_id=batch_id
            )

        # Step 3-5: Existing triage + policy evaluation
        gatherer = EvidenceGatherer(repo_root, budgets or BudgetConfig())
        classifier = StrictClassifier()

        triaged = []
        reportable = []

        for finding in findings:
            evidence = gatherer.gather(finding)
            classification = classifier.classify(finding, evidence, threat_model_profile)

            # Attach triage metadata
            triaged_finding = self._attach_triage_metadata(
                finding, classification, batch_id, policy_version
            )

            # Policy evaluation
            if policy:
                policy_result = self.policy_evaluator.evaluate(
                    finding, evidence, classification, policy
                )
                triaged_finding.policy_decision = policy_result.decision
                triaged_finding.policy_reasoning = policy_result.reasoning
                triaged_finding.path_classification = policy_result.path_classification

                # Track reportable based on policy decision
                if policy_result.decision in [
                    PolicyDecision.REPORT_SECURITY_VRP,
                    PolicyDecision.REPORT_SECURITY_LOW_CONFIDENCE
                ]:
                    reportable.append(triaged_finding)
            else:
                # Fallback: use disposition
                if classification.disposition in [
                    Disposition.VALID_SECURITY_ISSUE,
                    Disposition.BUG
                ]:
                    reportable.append(triaged_finding)

            triaged.append(triaged_finding)

        metrics = self._build_metrics(findings, triaged, reportable, 0)

        return TriageResult(
            triaged_findings=triaged,
            reportable_findings=reportable,
            metrics=metrics,
            batch_id=batch_id
        )
```

### CLI Integration

```bash
# Use VRP policy
python -m backend.cli triage --policy vrp-google-oss-strict

# Use environment variable
export TRIAGE_POLICY=vrp-google-oss-strict
python -m backend.cli triage
```

### API Endpoint

```python
@router.post("/api/triage")
async def triage_findings_endpoint(
    request: TriageRequest,
    policy_name: Optional[str] = Query(None, description="Policy name (e.g., vrp-google-oss-strict)")
):
    policy = None
    if policy_name:
        policy = load_policy(policy_name)  # Load from config

    result = triage_service.triage_findings(
        repo_root=request.repo_root,
        findings=request.findings,
        policy=policy,
        threat_model_profile=request.threat_model
    )

    return result
```

---

## Design: Testing Strategy

### Unit Tests

1. **PathClassification tests**
   - Test each root type (runtime/tooling/third_party/test/ci/docs/migrations)
   - Test priority order (third_party wins over runtime)
   - Test exact vs substring matching

2. **Pre-filter tests**
   - Test each filter flag (filter_third_party, filter_tests, etc.)
   - Test findings count reduction
   - Test path_classification attachment

3. **PolicyEvaluator tests**
   - Command injection gate (shell=True + string interpolation + boundary)
   - Integer overflow gate (operands + operation + allocation + mismatch)
   - Tooling boundary requirement
   - Disposition mapping

4. **Deduplication tests**
   - Exact match on all fields
   - Preserve first occurrence
   - Handle missing fields gracefully

### Integration Tests

1. **End-to-end with VRP policy**
   - Input: 100 findings (mix of runtime/test/third_party)
   - Expected: Only runtime findings with strict gates passed

2. **Command injection strictness**
   - Input: Shell injection vs argument injection findings
   - Expected: Only shell injection marked REPORT_VRP

3. **Integer overflow strictness**
   - Input: Speculative vs proven overflow findings
   - Expected: Only proven with allocation mismatch marked REPORT_VRP

---

## Implementation Plan

Will be written in separate `2026-01-17-vrp-strictness-implementation.md` plan.

**High-level tasks:**

1. Add TriagePolicy models to `models/schemas.py`
2. Implement path classification in `services/path_classifier.py`
3. Implement pre-filter in `services/pre_triage_filter.py`
4. Implement PolicyEvaluator in `services/policy_evaluator.py`
5. Implement deduplication in `services/deduplicator.py`
6. Update FindingTriageService to integrate all layers
7. Add VRP_GOOGLE_OSS_STRICT default policy
8. Add CLI/API integration
9. Write comprehensive tests
10. Update documentation

---

## Success Metrics

**Before VRP strictness:**
- Findings from test/tools/third_party: ~30%
- Command injection false positives: ~40%
- Integer overflow noise: ~60%
- Duplicates: ~20%
- VRP acceptance rate: ~30%

**After VRP strictness:**
- Findings from excluded paths: 0%
- Command injection false positives: <5%
- Integer overflow noise: <10%
- Duplicates: 0%
- VRP acceptance rate: >70%

---

## Open Questions

1. **Memory corruption gate**: Should we require ASan traces for all memory corruption, or just prefer them?
   - **Decision needed**: Start without requirement, add if false positive rate is high

2. **Tooling findings**: Should we have separate "tooling-strict" policy that reports tooling findings with weaker boundaries?
   - **Decision**: Start with single VRP policy, add variants later if needed

3. **Policy versioning**: How do we version policies and handle backwards compatibility?
   - **Decision**: Include policy version in TriageResult metadata, document breaking changes

4. **UI changes**: How should policy decisions be displayed in the UI?
   - **Decision**: Add "Policy Decision" badge (VRP / Low / Hardening / Filtered) next to disposition
