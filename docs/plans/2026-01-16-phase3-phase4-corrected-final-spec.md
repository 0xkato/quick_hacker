# Phase 3 & 4 Implementation Spec (Corrected Final)
**Evidence-Driven Input Channel Classification + Threat Model Gating + First-Party Focus**

**Date:** 2026-01-16
**Status:** Implementation Ready
**Owner:** 0xkato

---

## Critical Corrections Applied

1. ✅ **ToolExecutionContext lives with ToolCore** (`backend/agents/tools/context.py`)
2. ✅ **ChecklistItem keeps `value: bool`** with `Field(default_factory=list)` for lists
3. ✅ **Evidence extension strictly additive** with safe defaults
4. ✅ **Signal helpers as standalone functions** (not methods)
5. ✅ **Param binding uses intersection** (route params ∩ handler args)
6. ✅ **Budget manager in orchestrator** (correct placement)
7. ✅ **New fixture repo created** as specified
8. ✅ **Implementation starts with models + gating together** (not separately)

---

# Phase 3: Evidence-Driven Input Channel + Threat Model Gating

## 3.1 Data Model Changes

### 3.1.1 InputChannel Enum

**File:** `backend/models/schemas.py`

```python
class InputChannel(str, Enum):
    """
    Input channels represent where attacker-controlled data originates.

    Attacker-control is derived by: (deterministic channel + threat model profile)
    """
    network = "network"
    file_input = "file_input"
    web_content = "web_content"

    # High-noise channels (only attacker-controlled if enabled by profile)
    repo_checkout = "repo_checkout"
    ci_artifact = "ci_artifact"
    local_unprivileged = "local_unprivileged"

    unknown = "unknown"
```

### 3.1.2 Evidence Class Extension (Strictly Additive)

**File:** `backend/models/schemas.py`

**CRITICAL:** Extend existing `Evidence` class, do NOT rename. All new fields have safe defaults for backward compatibility with stored JSON.

```python
class Evidence(BaseModel):
    """
    Evidence bundle for triage classification.

    Persisted to evidence_json in database.
    """
    # Existing fields (keep as-is)
    finding_id: str
    handler_snippet: str | None = None
    route_registration: str | None = None
    auth_gates: list[str] = Field(default_factory=list)  # FIXED: default_factory
    dataflow_snippet: str | None = None
    symbol_info: dict | None = None
    # ... other existing fields ...

    # Phase 3 additions (all with safe defaults)
    input_channel: InputChannel = InputChannel.unknown
    input_channel_deterministic: bool = False

    # Auditable inference metadata (like checklist reason)
    input_channel_signals: list[str] = Field(default_factory=list)  # FIXED: default_factory
    input_channel_reason: str = ""
```

### 3.1.3 ChecklistItem Extension (Keep `value` Field)

**File:** `backend/models/schemas.py`

**CRITICAL:** Keep existing `value: bool` field. Stored JSON depends on it.

```python
class ChecklistItem(BaseModel):
    """Checklist item with tri-state status."""
    value: bool              # KEEP - existing field for stored JSON compatibility
    status: ChecklistStatus  # PROVEN_TRUE | PROVEN_FALSE | UNKNOWN
    reason: str              # Human-readable explanation
    tool_calls: list[str] = Field(default_factory=list)  # FIXED: default_factory

    # Phase 3 addition (backward-compatible)
    reason_code: str | None = None  # Machine-readable code (e.g., "disabled_by_profile")
```

---

## 3.2 Call Order and Function Signatures

### 3.2.1 Triage Entrypoint

**File:** `backend/services/finding_triage_service.py`

```python
class FindingTriageService:
    async def triage_findings(
        self,
        *,
        project_id: str,
        repo_root: str,
        findings: list[Finding],
        threat_model_profile: dict | None,
        project_scope: ProjectScope | None = None,  # Phase 4
        budgets: BudgetConfig | None = None,
        policy_version: str = "1.0.0",
    ) -> TriageResult:
        """
        Triage findings with threat model gating.

        Args:
            project_id: Project identifier
            repo_root: Repository root path
            findings: Raw findings from scanners/agents
            threat_model_profile: Per-project threat model (attacker capabilities)
            project_scope: Scope configuration (Phase 4)
            budgets: Time budgets for triage
            policy_version: Triage policy version

        Returns:
            TriageResult with triaged findings and metrics
        """
```

### 3.2.2 Evidence Gatherer

**File:** `backend/services/evidence_gatherer.py`

```python
class EvidenceGatherer:
    async def gather_evidence(
        self,
        *,
        finding: Finding,
        project_id: str,
        repo_root: str,
        project_scope: ProjectScope | None = None,  # Phase 4
    ) -> Evidence:
        """
        Gather evidence and infer input channel.

        MUST populate Evidence.input_channel* fields.

        Args:
            finding: Raw finding to gather evidence for
            project_id: Project identifier
            repo_root: Repository root path
            project_scope: Scope configuration (Phase 4)

        Returns:
            Evidence with input_channel fields populated
        """
        # Existing evidence gathering
        evidence = await self._gather_base_evidence(
            finding=finding,
            repo_root=repo_root,
        )

        # Phase 3: Infer input channel (delegates to standalone module)
        from services.input_channel_inference import infer_input_channel
        infer_input_channel(finding=finding, evidence=evidence)

        return evidence
```

### 3.2.3 StrictClassifier

**File:** `backend/services/strict_classifier.py`

```python
class StrictClassifier:
    def classify(
        self,
        *,
        finding: Finding,
        evidence: Evidence,
        threat_model_profile: dict | None = None,
    ) -> ClassificationResult:
        """
        Classify finding with threat model gating.

        Args:
            finding: Finding to classify
            evidence: Evidence bundle (includes input_channel)
            threat_model_profile: Per-project threat model

        Returns:
            ClassificationResult with disposition, checklist, reasoning
        """
        # Build checklist with gating FIRST
        checklist = self._build_proof_checklist(
            finding=finding,
            evidence=evidence,
            threat_model_profile=threat_model_profile,
        )

        # Apply rules (gating already done in checklist)
        disposition = self._apply_rules(
            finding=finding,
            evidence=evidence,
            checklist=checklist,
        )

        # Generate reasoning (coherent with gated checklist)
        reasoning = self._generate_reasoning(
            finding=finding,
            evidence=evidence,
            checklist=checklist,
            disposition=disposition,
        )

        return ClassificationResult(
            disposition=disposition,
            proof_checklist=checklist,
            reasoning=reasoning,
            # ... confidence scores ...
        )
```

### 3.2.4 Pipeline Sequence

**File:** `backend/services/finding_triage_service.py`

```python
async def triage_findings(self, ...) -> TriageResult:
    gatherer = EvidenceGatherer()
    classifier = StrictClassifier()

    triaged = []
    for finding in findings:
        # 1. Gather evidence (input_channel inferred here)
        evidence = await gatherer.gather_evidence(
            finding=finding,
            project_id=project_id,
            repo_root=repo_root,
            project_scope=project_scope,
        )

        # 2. Classify (gating happens in checklist construction)
        classification = classifier.classify(
            finding=finding,
            evidence=evidence,
            threat_model_profile=threat_model_profile,
        )

        # 3. Attach metadata
        triaged.append(
            self._attach_triage_metadata(
                finding=finding,
                evidence=evidence,
                classification=classification,
                policy_version=policy_version,
            )
        )

    return TriageResult(findings=triaged, metrics=self._compute_metrics(triaged))
```

---

## 3.3 Threat Model Gating at Checklist Construction

### 3.3.1 Derive Allowed Channels

**File:** `backend/services/threat_model_gating.py` (new file)

```python
"""
Threat model gating logic.

Provides canonical mapping from threat model profile to allowed input channels.
"""

from models.schemas import InputChannel


def derive_allowed_input_channels(threat_model_profile: dict | None) -> set[InputChannel]:
    """
    Derive which input channels are enabled by the threat model profile.

    Args:
        threat_model_profile: Project threat model profile dict

    Returns:
        Set of allowed InputChannel enums
    """
    if not threat_model_profile:
        # No profile = no gating (preserve legacy behavior)
        return set(InputChannel)

    caps = set(threat_model_profile.get("attacker_capabilities", []))

    # Canonical mapping: attacker capability → input channels
    cap_to_channels: dict[str, set[InputChannel]] = {
        "remote_network": {InputChannel.network},
        "untrusted_file_input": {InputChannel.file_input},
        "remote_web_content": {InputChannel.web_content},
        "untrusted_repo_content": {InputChannel.repo_checkout},
        "untrusted_ci_artifact": {InputChannel.ci_artifact},
        "local_unprivileged_user": {InputChannel.local_unprivileged},
    }

    allowed: set[InputChannel] = set()
    for cap in caps:
        allowed |= cap_to_channels.get(cap, set())

    # Always allow unknown (non-deterministic won't gate anyway)
    allowed.add(InputChannel.unknown)

    return allowed
```

### 3.3.2 Checklist Gating Logic

**File:** `backend/services/strict_classifier.py`

```python
from services.threat_model_gating import derive_allowed_input_channels

def _build_proof_checklist(
    self,
    *,
    finding: Finding,
    evidence: Evidence,
    threat_model_profile: dict | None,
) -> ProofChecklist:
    """
    Build proof checklist with threat model gating applied FIRST.

    This ensures disposition and reasoning are coherent with gated truth.
    """
    # Derive allowed channels from profile
    allowed = derive_allowed_input_channels(threat_model_profile)

    # Check if gating should apply
    gated_off = (
        evidence.input_channel_deterministic
        and evidence.input_channel != InputChannel.unknown
        and evidence.input_channel not in allowed
    )

    # Build source_controlled_input item
    if gated_off:
        # Force PROVEN_FALSE due to profile
        source_controlled_input = ChecklistItem(
            value=False,  # KEEP - required field
            status=ChecklistStatus.PROVEN_FALSE,
            reason=(
                f"disabled_by_profile: input_channel={evidence.input_channel.value} "
                f"allowed={sorted([c.value for c in allowed])}; "
                f"signals={evidence.input_channel_signals}; "
                f"why={evidence.input_channel_reason}"
            ),
            reason_code="disabled_by_profile",
        )
    else:
        # Evaluate normally from evidence
        source_controlled_input = self._evaluate_source_controlled_input(
            finding, evidence
        )

    # Build remaining checklist items (normal evaluation)
    return ProofChecklist(
        source_controlled_input=source_controlled_input,
        sink_present=self._evaluate_sink_present(finding, evidence),
        dataflow_evidenced=self._evaluate_dataflow(finding, evidence),
        reachable=self._evaluate_reachable(finding, evidence),
        boundary_crossed=self._evaluate_boundary_crossed(finding, evidence),
        not_only_misconfig=self._evaluate_not_only_misconfig(finding, evidence),
        security_control_bypassed=self._evaluate_security_control_bypassed(
            finding, evidence
        ),
        # ... keep remaining fields as-is ...
    )
```

### 3.3.3 Rule 0: Gated Input Forces HARDENING

**File:** `backend/services/strict_classifier.py`

```python
def _apply_rules(
    self,
    finding: Finding,
    evidence: Evidence,
    checklist: ProofChecklist,
) -> Disposition:
    """
    Apply disposition rules in priority order.
    """
    # RULE 0: Threat-model gated input => HARDENING
    # (Must be first to prevent other rules from overriding)
    if checklist.source_controlled_input.reason_code == "disabled_by_profile":
        return Disposition.HARDENING

    # Existing rules continue below (unchanged)
    # ... RULE 1: exec/eval feature detection
    # ... RULE 2: MISCONFIGURATION check
    # ... etc.
```

---

## 3.4 Evidence-Driven Channel Inference

### 3.4.1 Standalone Inference Module

**File:** `backend/services/input_channel_inference.py` (new file)

```python
"""
Input channel inference logic.

Infers input channel from evidence using 2-signal minimum.
Keeps EvidenceGatherer from becoming a monolith of regexes.
"""

from models.schemas import Finding, Evidence, InputChannel


def infer_input_channel(*, finding: Finding, evidence: Evidence) -> None:
    """
    Infer input channel from evidence (mutates evidence in-place).

    Conservative: default unknown unless 2-signal threshold met.

    Args:
        finding: Finding being analyzed
        evidence: Evidence bundle (mutated in-place)
    """
    # Default
    evidence.input_channel = InputChannel.unknown
    evidence.input_channel_deterministic = False
    evidence.input_channel_signals = []
    evidence.input_channel_reason = ""

    # Helper to set deterministic channel
    def set_deterministic(ch: InputChannel, signals: list[str], reason: str):
        evidence.input_channel = ch
        evidence.input_channel_deterministic = True
        evidence.input_channel_signals = signals
        evidence.input_channel_reason = reason

    # Precedence order (prevents overlaps)

    # 1) WebSocket network
    signals = _collect_websocket_signals(evidence)
    if {"websocket_registration", "websocket_message_read"} <= set(signals):
        return set_deterministic(
            InputChannel.network,
            signals,
            "ws registration + message read"
        )

    # 2) HTTP network
    signals = _collect_http_signals(evidence)
    if "route_registration" in signals and (
        "request_data_read" in signals or "framework_param_binding" in signals
    ):
        return set_deterministic(
            InputChannel.network,
            signals,
            "route + request/binding"
        )

    # 3) File input
    signals = _collect_file_signals(evidence)
    if "file_upload_api" in signals and (
        "external_file_read" in signals or "file_parse_operation" in signals
    ):
        return set_deterministic(
            InputChannel.file_input,
            signals,
            "upload + read/parse"
        )

    # 4) Web content
    signals = _collect_web_signals(evidence)
    if "dom_sink_use" in signals and (
        "browser_source_read" in signals or "message_event_handler" in signals
    ):
        return set_deterministic(
            InputChannel.web_content,
            signals,
            "browser/message source + dom sink"
        )

    # 5) Repo checkout (ultra-conservative)
    signals = _collect_repo_signals(evidence)
    if "repo_content_ingested" in signals and (
        "repo_content_read_as_data" in signals or "ci_context_marker" in signals
    ):
        return set_deterministic(
            InputChannel.repo_checkout,
            signals,
            "repo/ci content ingested"
        )

    # else remains unknown


# Signal collection helpers

def _collect_http_signals(evidence: Evidence) -> list[str]:
    """Collect HTTP/REST signals from evidence."""
    signals = []

    # Signal 1: Route registration
    if _has_route_registration(evidence):
        signals.append("route_registration")

    # Signal 2a: Request data read
    if _has_request_data_read(evidence):
        signals.append("request_data_read")

    # Signal 2b: Framework parameter binding
    if _has_framework_param_binding(evidence):
        signals.append("framework_param_binding")

    return signals


def _has_framework_param_binding(evidence: Evidence) -> bool:
    """
    Check if framework binds route params to handler args.

    Uses route template params ∩ handler args intersection.
    Tier 1: AST-based (preferred)
    Tier 2: Heuristic fallback
    """
    # Tier 1: AST-based (preferred)
    if evidence.symbol_info and evidence.route_registration:
        route_params = _extract_route_params(evidence.route_registration)
        handler_args = _extract_handler_args(evidence.symbol_info)

        # If route params overlap with handler args, binding detected
        if route_params & handler_args:
            return True

    # Tier 2: Heuristic fallback
    if evidence.route_registration and evidence.handler_snippet:
        import re

        # Extract params from route template
        route_params = _extract_route_params(evidence.route_registration)

        # Extract args from handler signature
        handler_match = re.search(r'def\s+\w+\s*\(([^)]+)\)', evidence.handler_snippet)
        if handler_match:
            args_str = handler_match.group(1)
            handler_args = set(re.findall(r'(\w+)\s*(?::|,|$)', args_str))

            if route_params & handler_args:
                return True

    return False


def _extract_route_params(route: str) -> set[str]:
    """Extract parameter names from route template."""
    import re

    params = set()
    # FastAPI/Starlette: {user_id}
    params |= set(re.findall(r'\{(\w+)\}', route))
    # Flask: <user_id> or <int:user_id>
    params |= set(re.findall(r'<(?:\w+:)?(\w+)>', route))
    # Express: :user_id
    params |= set(re.findall(r':(\w+)', route))

    return params


def _extract_handler_args(symbol_info: dict) -> set[str]:
    """Extract function argument names from symbol info."""
    args = set()

    if "args" in symbol_info:
        for arg in symbol_info["args"]:
            if isinstance(arg, dict) and "name" in arg:
                args.add(arg["name"])
            elif isinstance(arg, str):
                args.add(arg)

    return args


# Implement remaining signal detection functions
# (pattern matching on evidence fields - similar to above)
```

---

# Phase 4: First-Party Focus

## 4.1 Data Models

### 4.1.1 ProjectScope Model

**File:** `backend/models/schemas.py`

```python
class ProjectScope(BaseModel):
    """
    Scope configuration for First-Party Focus.

    Defines which code paths are "product code" vs "library code".
    """
    primary_code_roots: list[str] = Field(
        default_factory=lambda: ["src/", "app/", "backend/", "frontend/"]
    )

    excluded_roots: list[str] = Field(
        default_factory=lambda: [
            "vendor/", "third_party/", "node_modules/",
            ".venv/", "site-packages/", "dist/", "build/",
            "target/", "out/"
        ]
    )

    treat_excluded_as_supporting_evidence_only: bool = True


class Project(BaseModel):
    # ... existing fields ...
    scope: ProjectScope = Field(default_factory=ProjectScope)
```

### 4.1.2 File Origin Classification

**File:** `backend/services/file_origin.py` (new file)

```python
"""File origin classification for First-Party Focus."""

from enum import Enum
from pathlib import Path
from models.schemas import ProjectScope


class FileOrigin(str, Enum):
    first_party = "first_party"
    third_party = "third_party"
    test = "test"
    generated = "generated"
    external = "external"
    unknown = "unknown"


def to_repo_relative(repo_root: str, path: str) -> str:
    """Convert path to repo-relative path."""
    rr = Path(repo_root).resolve()
    p = Path(path).resolve() if Path(path).is_absolute() else (rr / path).resolve()

    try:
        rel = p.relative_to(rr)
        return str(rel).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def classify_file_origin(
    *,
    repo_root: str,
    file_path: str,
    scope: ProjectScope
) -> FileOrigin:
    """Classify file origin based on path and scope."""
    rel = to_repo_relative(repo_root, file_path)

    # Outside repo => external
    if rel.startswith("/") or (":" in rel[:4]):
        return FileOrigin.external

    # Excluded roots (match anywhere in path)
    for excluded in scope.excluded_roots:
        excluded_norm = excluded.rstrip("/")
        if (
            rel == excluded_norm
            or rel.startswith(f"{excluded_norm}/")
            or f"/{excluded_norm}/" in f"/{rel}"
        ):
            return FileOrigin.third_party

    # Test files
    test_markers = ["test/", "tests/", "__tests__/"]
    test_suffixes = [".spec.", ".test."]
    if any(m in rel for m in test_markers) or any(s in rel for s in test_suffixes):
        return FileOrigin.test

    # Generated code
    if "generated/" in rel or ".generated." in rel:
        return FileOrigin.generated

    # Primary code roots
    if any(rel.startswith(pr) for pr in scope.primary_code_roots):
        return FileOrigin.first_party

    return FileOrigin.unknown
```

---

## 4.2 Tool Execution Context Pattern

### 4.2.1 ToolExecutionContext

**File:** `backend/agents/tools/context.py` (new file)

**CRITICAL:** Place alongside existing ToolCore, NOT in `backend/services/`.

```python
"""
Tool execution context for First-Party Focus.

Provides scope filtering and budget management without changing tool schemas.
"""

from pydantic import BaseModel
from models.schemas import ProjectScope


class ToolExecutionContext(BaseModel):
    """
    Context passed to all tools for scope filtering and budget attribution.

    This keeps tool schemas unchanged (preserves Claude SDK compatibility).
    """
    project_id: str
    repo_root: str
    project_scope: ProjectScope | None = None
    budget_manager: "ToolBudgetManager | None" = None
```

### 4.2.2 Update ToolCore Base Class

**File:** `backend/agents/tools/base.py` (existing file)

```python
from agents.tools.context import ToolExecutionContext

class ToolCore:
    """Base class for all tools."""

    def __init__(self, ctx: ToolExecutionContext):
        self.ctx = ctx

    # ... existing tool methods ...
```

### 4.2.3 Instantiate in Orchestrator

**File:** `backend/agents/orchestrator.py` (or wherever tools are built)

```python
from agents.tools.context import ToolExecutionContext
from services.tool_budget_manager import ToolBudgetManager

class AgentOrchestrator:
    def create_tools(
        self,
        *,
        project: Project,
        repo_root: str,
        budgets: BudgetConfig,
    ) -> list[ToolCore]:
        """Create tools with scope filtering and budget management."""
        # Create budget manager (80/20 split)
        budget_mgr = ToolBudgetManager(total_ms=budgets.tool_total_ms)

        # Create execution context
        ctx = ToolExecutionContext(
            project_id=project.id,
            repo_root=repo_root,
            project_scope=project.scope,
            budget_manager=budget_mgr,
        )

        # Create tools (all receive same context)
        tools = [
            RipgrepTool(ctx),
            ReadFileTool(ctx),
            ListFilesTool(ctx),
            # ... other tools ...
        ]

        return tools
```

---

## 4.3 Tool Budget Manager

**File:** `backend/services/tool_budget_manager.py` (new file)

```python
"""Tool budget manager for First-Party Focus."""

from services.file_origin import FileOrigin

# Budget bucket constants
BUCKET_FIRST_PARTY = "first_party"
BUCKET_THIRD_PARTY = "third_party"


class ThirdPartyBudgetExceeded(Exception):
    """Third-party budget exhausted."""
    pass


class FirstPartyBudgetExceeded(Exception):
    """First-party budget exhausted."""
    pass


class ToolBudgetManager:
    """
    Manages tool execution budget split between first-party and third-party code.

    80/20 split: 80% for first-party, 20% for third-party (supporting evidence).
    """

    def __init__(self, total_ms: int):
        self.total_ms = total_ms
        self.first_party_ms_limit = int(total_ms * 0.80)
        self.third_party_ms_limit = total_ms - self.first_party_ms_limit

        self.first_party_ms_used = 0
        self.third_party_ms_used = 0

    def charge(self, origin: FileOrigin, duration_ms: int) -> None:
        """
        Charge tool execution time to appropriate budget bucket.

        Args:
            origin: File origin classification
            duration_ms: Tool execution duration in milliseconds

        Raises:
            ThirdPartyBudgetExceeded: If third-party budget exhausted
            FirstPartyBudgetExceeded: If first-party budget exhausted
        """
        if origin in {FileOrigin.third_party, FileOrigin.external}:
            if self.third_party_ms_used + duration_ms > self.third_party_ms_limit:
                raise ThirdPartyBudgetExceeded(
                    self._format_exhausted_error(BUCKET_THIRD_PARTY)
                )
            self.third_party_ms_used += duration_ms
        else:
            # Treat unknown/test/generated as first_party bucket
            if self.first_party_ms_used + duration_ms > self.first_party_ms_limit:
                raise FirstPartyBudgetExceeded(
                    self._format_exhausted_error(BUCKET_FIRST_PARTY)
                )
            self.first_party_ms_used += duration_ms

    def _format_exhausted_error(self, bucket: str) -> str:
        """Format budget exhausted error with actionable message."""
        stats = self.get_stats()
        bucket_stats = stats[bucket]  # FIXED: matches get_stats() keys

        # Display with hyphen for readability
        display_name = bucket.replace("_", "-").capitalize()

        return (
            f"{display_name} budget exhausted: "
            f"{bucket_stats['used_ms']}ms used, {bucket_stats['limit_ms']}ms limit. "
            f"Narrow your search to first-party roots or justify entering "
            f"dependencies for a concrete dataflow path."
        )

    def get_stats(self) -> dict:
        """Get budget usage statistics."""
        return {
            BUCKET_FIRST_PARTY: {
                "limit_ms": self.first_party_ms_limit,
                "used_ms": self.first_party_ms_used,
                "remaining_ms": self.first_party_ms_limit - self.first_party_ms_used,
            },
            BUCKET_THIRD_PARTY: {
                "limit_ms": self.third_party_ms_limit,
                "used_ms": self.third_party_ms_used,
                "remaining_ms": self.third_party_ms_limit - self.third_party_ms_used,
            },
        }
```

---

## 4.4 Test Fixture Repo

### Location and Structure

**Path:** `backend/tests/fixtures/repos/phase3_phase4_repo/`

```
phase3_phase4_repo/
├── src/
│   └── api.py                 # FastAPI route with {param} + handler
│       # Contains: network SQLi (deterministic)
│
├── helpers/
│   └── request_utils.py       # Helper using request without route
│       # Should stay unknown (non-deterministic)
│
├── uploads/
│   └── parser.py              # File upload + parse
│       # Contains: file_input XXE (deterministic)
│
├── .github/
│   └── workflows/
│       └── ci.yml             # Repo content ingestion
│           # Contains: repo_checkout command injection
│
└── node_modules/
    └── debug/
        └── index.js           # Third-party code with "vulns"
            # Should not originate findings by default
```

---

## Implementation Order (Corrected)

### PR 1: Phase 3 Models + Gating + Rule 0

**Do together as one cohesive slice:**

1. Data models
   - Add `InputChannel` enum
   - Extend `Evidence` (strictly additive, safe defaults)
   - Extend `ChecklistItem` (keep `value`, add `reason_code`)

2. Threat model gating
   - Create `backend/services/threat_model_gating.py`
   - Implement `derive_allowed_input_channels()`
   - Update `StrictClassifier._build_proof_checklist()`
   - Add Rule 0 to `_apply_rules()`

3. Unit tests (Tier 0)
   - Test gating with hand-constructed Evidence objects
   - Test derive_allowed_input_channels()
   - Test Rule 0 disposition

### PR 2: Phase 3 Inference + Integration

4. Channel inference
   - Create `backend/services/input_channel_inference.py`
   - Implement `infer_input_channel()`
   - Implement signal collection helpers
   - Implement signal detection functions

5. EvidenceGatherer integration
   - Update `gather_evidence()` to call inference

6. Unit tests (Tier 0)
   - Test inference with various evidence patterns
   - Test 2-signal minimum
   - Test param binding detection

### PR 3: Phase 4 Scope + Budget + Tests

7. Phase 4 data models
   - Add `ProjectScope` to `Project`
   - Create `backend/services/file_origin.py`

8. Tool context pattern
   - Create `backend/agents/tools/context.py`
   - Update `ToolCore` base class
   - Create `backend/services/tool_budget_manager.py`

9. Scanner filtering
   - Update `should_scan_file()` in scanners

10. Test fixture + integration tests
    - Create fixture repo
    - Tier 1: Tool behavior tests
    - Tier 2: Budget manager tests
    - Tier 3: End-to-end with fixture

---

## Final "No Steps Backward" Checklist

Before merging, ALL must pass:

### Phase 3 Invariants
- [ ] `Evidence` class extended (not renamed)
- [ ] `ChecklistItem.value` preserved
- [ ] All list fields use `Field(default_factory=list)`
- [ ] Gating occurs in `_build_proof_checklist()`
- [ ] Rule 0 first in `_apply_rules()`
- [ ] `InputChannel` never inferred from file path
- [ ] Framework param binding uses intersection
- [ ] Unknown proof gaps → SPECULATIVE
- [ ] Network findings never gated (preset A)

### Phase 4 Invariants
- [ ] `ToolExecutionContext` in `backend/agents/tools/`
- [ ] Budget manager keys consistent (underscores)
- [ ] Absolute-path classification correct
- [ ] Budget exhaustion returns structured error
- [ ] Findings don't originate from excluded roots
- [ ] ReadFile works on excluded roots
- [ ] Tool schemas unchanged (Claude SDK safe)

### Test Coverage
- [ ] All Tier 0 unit tests pass
- [ ] All Tier 1 tool tests pass
- [ ] All Tier 2 budget tests pass
- [ ] All Tier 3 fixture repo tests pass

---

**Document Owner:** 0xkato
**Status:** Ready for Implementation
**Last Updated:** 2026-01-16 (Corrected Final)
