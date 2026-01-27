# LLM-Based Secondary Validation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add agentic LLM validation layer to triage system that deeply validates findings for reachability and attacker control, reducing false positives.

**Architecture:** Two-tier validation (fast filter + deep agentic investigation). Pre-validation gates filter 60-80% before expensive LLM. LLM validator uses tool calls (Read/Grep/Glob) to prove exploitability with high skepticism.

**Tech Stack:** Python 3.11+, Anthropic Claude API, Pydantic, pytest, TypeScript/React

---

## Task 1: Add ValidationResult Schema

**Files:**
- Modify: `backend/models/schemas.py` (add ValidationResult, update Finding and ProtocolPolicy)
- Test: `backend/tests/models/test_schemas.py`

**Step 1: Write test for ValidationResult model**

```python
# In backend/tests/models/test_schemas.py

def test_validation_result_creation():
    """Test ValidationResult can be created with all fields."""
    from models.schemas import ValidationResult
    from datetime import datetime

    result = ValidationResult(
        is_valid=True,
        reasoning=["Finding is exploitable", "Attacker can control input"],
        categories=["security_issue"],
        investigation_steps=["Read file", "Grep for calls"],
        confidence=95
    )

    assert result.is_valid == True
    assert len(result.reasoning) == 2
    assert result.categories == ["security_issue"]
    assert result.confidence == 95
    assert isinstance(result.timestamp, datetime)

def test_validation_result_minimal():
    """Test ValidationResult with minimal fields."""
    from models.schemas import ValidationResult

    result = ValidationResult(
        is_valid=False,
        reasoning=["Not exploitable"],
        categories=["hardening"]
    )

    assert result.is_valid == False
    assert result.investigation_steps is None
    assert result.confidence is None
```

**Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/models/test_schemas.py::test_validation_result_creation -v
```

Expected: FAIL with "ImportError: cannot import name 'ValidationResult'"

**Step 3: Add ValidationResult to schemas.py**

```python
# In backend/models/schemas.py, after ChecklistStatus enum

class ValidationResult(BaseModel):
    """Result from LLM-based finding validation."""
    is_valid: bool
    reasoning: list[str]  # Bullet points explaining decision
    categories: list[str]  # e.g., ["security_issue"], ["hardening", "by_design"]
    investigation_steps: Optional[list[str]] = None  # Tool calls made
    confidence: Optional[int] = None  # 0-100, validator's confidence
    timestamp: datetime = Field(default_factory=datetime.utcnow)
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/models/test_schemas.py::test_validation_result_creation -v
pytest tests/models/test_schemas.py::test_validation_result_minimal -v
```

Expected: PASS (both tests)

**Step 5: Add validation_result field to Finding**

```python
# In backend/models/schemas.py, in Finding class after submission_result field

class Finding(BaseModel):
    # ... existing fields ...

    # Protocol evaluation
    submission_result: Optional[SubmissionResult] = None

    # NEW: Validation result from LLM validator
    validation_result: Optional[ValidationResult] = None
```

**Step 6: Write test for Finding with validation_result**

```python
# In backend/tests/models/test_schemas.py

def test_finding_with_validation_result():
    """Test Finding can include validation_result."""
    from models.schemas import Finding, ValidationResult, Severity

    validation = ValidationResult(
        is_valid=True,
        reasoning=["Exploitable"],
        categories=["security_issue"]
    )

    finding = Finding(
        id="test-1",
        title="Test Finding",
        description="Test",
        file_path="test.py",
        line_start=10,
        vulnerability_type="command_injection",
        severity=Severity.HIGH,
        code_snippet="exec(user_input)",
        validation_result=validation
    )

    assert finding.validation_result is not None
    assert finding.validation_result.is_valid == True
```

**Step 7: Run test to verify it passes**

```bash
pytest tests/models/test_schemas.py::test_finding_with_validation_result -v
```

Expected: PASS

**Step 8: Add LLM validation fields to ProtocolPolicy**

```python
# In backend/models/schemas.py, in ProtocolPolicy class after existing fields

class ProtocolPolicy(BaseModel):
    # ... existing fields ...

    # NEW: LLM validation settings
    enable_llm_validation: bool = True  # Default enabled, can be disabled
    validation_criticism_level: Literal["high", "medium", "low"] = "high"
    validation_model: Optional[str] = None  # Override model
    validation_timeout_seconds: int = 120  # Per-finding timeout
    validation_fallback_on_error: Literal["invalid", "valid", "skip"] = "invalid"
```

**Step 9: Write test for ProtocolPolicy with validation settings**

```python
# In backend/tests/models/test_schemas.py

def test_protocol_policy_with_validation_settings():
    """Test ProtocolPolicy with LLM validation settings."""
    from models.schemas import ProtocolPolicy, Disposition

    policy = ProtocolPolicy(
        id="test-policy",
        display_name="Test Policy",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE],
        min_checklist_proven_count=4,
        enable_llm_validation=True,
        validation_criticism_level="high",
        validation_timeout_seconds=60
    )

    assert policy.enable_llm_validation == True
    assert policy.validation_criticism_level == "high"
    assert policy.validation_timeout_seconds == 60
    assert policy.validation_fallback_on_error == "invalid"  # default

def test_protocol_policy_validation_disabled():
    """Test ProtocolPolicy with validation disabled."""
    from models.schemas import ProtocolPolicy, Disposition

    policy = ProtocolPolicy(
        id="test-policy",
        display_name="Test Policy",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE],
        min_checklist_proven_count=4,
        enable_llm_validation=False
    )

    assert policy.enable_llm_validation == False
```

**Step 10: Run tests to verify they pass**

```bash
pytest tests/models/test_schemas.py::test_protocol_policy_with_validation_settings -v
pytest tests/models/test_schemas.py::test_protocol_policy_validation_disabled -v
```

Expected: PASS (both tests)

**Step 11: Commit**

```bash
git add backend/models/schemas.py backend/tests/models/test_schemas.py
git commit -m "feat(triage): add ValidationResult schema and validation settings to ProtocolPolicy

Add ValidationResult model for LLM validation results with is_valid flag, reasoning bullets, categories, investigation steps, and confidence score.

Add validation_result field to Finding model (optional).

Add LLM validation settings to ProtocolPolicy: enable_llm_validation (default true), validation_criticism_level (high/medium/low), validation_model override, timeout, and error fallback behavior.

Tests included for all new models and fields."
```

---

## Task 2: Create Pre-Validation Gates

**Files:**
- Create: `backend/services/validation/__init__.py`
- Create: `backend/services/validation/pre_validation_gates.py`
- Test: `backend/tests/services/validation/test_pre_validation_gates.py`

**Step 1: Create validation module directory**

```bash
mkdir -p backend/services/validation
mkdir -p backend/tests/services/validation
```

**Step 2: Create __init__.py with exports**

```python
# In backend/services/validation/__init__.py

"""Validation services for finding triage."""

from .pre_validation_gates import PreValidationGates

__all__ = ["PreValidationGates"]
```

**Step 3: Write test for disposition gate**

```python
# In backend/tests/services/validation/test_pre_validation_gates.py

import pytest
from models.schemas import (
    Finding, Evidence, ProtocolPolicy, Disposition,
    ChecklistItem, ChecklistStatus, ProofChecklist, Severity
)
from services.classification import ClassificationResult
from services.validation import PreValidationGates


@pytest.fixture
def mock_finding():
    return Finding(
        id="test-1",
        title="Command Injection",
        description="exec with user input",
        file_path="app.py",
        line_start=10,
        vulnerability_type="command_injection",
        severity=Severity.HIGH,
        code_snippet="exec(user_input)"
    )


@pytest.fixture
def mock_evidence():
    return Evidence(
        finding_id="test-1",
        snippet="exec(user_input)",
        matches=[],
        timed_out=False,
        input_channel="network",
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP endpoint"
    )


@pytest.fixture
def mock_protocol_policy():
    return ProtocolPolicy(
        id="strict-policy",
        display_name="Strict Policy",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE, Disposition.BUG],
        min_checklist_proven_count=4
    )


def test_disposition_gate_rejects_low_disposition(mock_finding, mock_evidence, mock_protocol_policy):
    """Test gate rejects findings with disposition below threshold."""
    gates = PreValidationGates()

    classification = ClassificationResult(
        disposition=Disposition.HARDENING,  # Below threshold
        classification_confidence=80,
        exploit_confidence=None,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            sink_present=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            dataflow_evidenced=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            reachable=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            boundary_crossed=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            not_only_misconfig=ChecklistItem(True, ChecklistStatus.PROVEN, "test")
        ),
        reasoning=["Test"],
        category="command_injection"
    )

    result = gates.check_gates(mock_finding, mock_evidence, classification, mock_protocol_policy)

    assert result is not None
    assert result.is_valid == False
    assert "filtered_by_disposition" in result.categories
    assert "Disposition hardening below threshold" in result.reasoning[0]


def test_disposition_gate_passes_high_disposition(mock_finding, mock_evidence, mock_protocol_policy):
    """Test gate passes findings with disposition above threshold."""
    gates = PreValidationGates()

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,  # Above threshold
        classification_confidence=95,
        exploit_confidence=85,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            sink_present=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            dataflow_evidenced=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            reachable=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            boundary_crossed=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            not_only_misconfig=ChecklistItem(True, ChecklistStatus.PROVEN, "test")
        ),
        reasoning=["Test"],
        category="command_injection"
    )

    result = gates.check_gates(mock_finding, mock_evidence, classification, mock_protocol_policy)

    # Should pass disposition gate (may fail checklist gate or pass entirely)
    if result is not None:
        assert "filtered_by_disposition" not in result.categories
```

**Step 4: Run test to verify it fails**

```bash
cd backend
pytest tests/services/validation/test_pre_validation_gates.py::test_disposition_gate_rejects_low_disposition -v
```

Expected: FAIL with "ImportError: cannot import name 'PreValidationGates'"

**Step 5: Implement PreValidationGates class**

```python
# In backend/services/validation/pre_validation_gates.py

"""Pre-validation gates - fast rule-based checks before expensive LLM validation."""

from typing import Optional
from models.schemas import (
    Finding, Evidence, ProtocolPolicy, ValidationResult,
    ChecklistStatus, Disposition
)
from services.classification import ClassificationResult


class PreValidationGates:
    """Fast rule-based gates that run before LLM validator to save API costs."""

    def check_gates(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        protocol_policy: ProtocolPolicy
    ) -> Optional[ValidationResult]:
        """
        Run pre-validation gates.

        Returns ValidationResult if should be filtered, None if should proceed to LLM.
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

        # Gate 3: Social engineering detection
        if protocol_policy.reject_social_engineering_only:
            description_lower = finding.description.lower()
            social_eng_markers = [
                "user must paste",
                "trick the user",
                "convince user to",
                "user needs to manually",
                "requires user to open",
                "phishing",
                "social engineering"
            ]

            if any(marker in description_lower for marker in social_eng_markers):
                return ValidationResult(
                    is_valid=False,
                    reasoning=[
                        "Attack requires social engineering / user cooperation",
                        "No realistic remote attacker scenario"
                    ],
                    categories=["social_engineering"]
                )

        # All gates passed
        return None
```

**Step 6: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_pre_validation_gates.py::test_disposition_gate_rejects_low_disposition -v
pytest tests/services/validation/test_pre_validation_gates.py::test_disposition_gate_passes_high_disposition -v
```

Expected: PASS (both tests)

**Step 7: Write test for checklist quality gate**

```python
# In backend/tests/services/validation/test_pre_validation_gates.py

def test_checklist_gate_rejects_insufficient_evidence(mock_finding, mock_evidence, mock_protocol_policy):
    """Test gate rejects findings with too few proven checklist items."""
    gates = PreValidationGates()

    # Only 2 PROVEN items (need 4)
    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=60,
        exploit_confidence=None,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            sink_present=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            dataflow_evidenced=ChecklistItem(False, ChecklistStatus.UNKNOWN, "test"),
            reachable=ChecklistItem(False, ChecklistStatus.UNKNOWN, "test"),
            boundary_crossed=ChecklistItem(False, ChecklistStatus.UNKNOWN, "test"),
            not_only_misconfig=ChecklistItem(False, ChecklistStatus.UNKNOWN, "test")
        ),
        reasoning=["Test"],
        category="command_injection"
    )

    result = gates.check_gates(mock_finding, mock_evidence, classification, mock_protocol_policy)

    assert result is not None
    assert result.is_valid == False
    assert "insufficient_evidence" in result.categories
    assert "Only 2/4 checklist items proven" in result.reasoning[0]
```

**Step 8: Run test to verify it passes**

```bash
pytest tests/services/validation/test_pre_validation_gates.py::test_checklist_gate_rejects_insufficient_evidence -v
```

Expected: PASS

**Step 9: Write test for all gates passing**

```python
# In backend/tests/services/validation/test_pre_validation_gates.py

def test_all_gates_pass(mock_finding, mock_evidence, mock_protocol_policy):
    """Test when all gates pass, returns None to proceed to LLM."""
    gates = PreValidationGates()

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,  # Passes disposition gate
        classification_confidence=95,
        exploit_confidence=85,
        proof_checklist=ProofChecklist(  # 6 PROVEN items (exceeds min 4)
            source_controlled_input=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            sink_present=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            dataflow_evidenced=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            reachable=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            boundary_crossed=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            not_only_misconfig=ChecklistItem(True, ChecklistStatus.PROVEN, "test")
        ),
        reasoning=["Test"],
        category="command_injection"
    )

    result = gates.check_gates(mock_finding, mock_evidence, classification, mock_protocol_policy)

    assert result is None  # No gate triggered, proceed to LLM
```

**Step 10: Run test to verify it passes**

```bash
pytest tests/services/validation/test_pre_validation_gates.py::test_all_gates_pass -v
```

Expected: PASS

**Step 11: Run all tests for pre-validation gates**

```bash
pytest tests/services/validation/test_pre_validation_gates.py -v
```

Expected: All tests PASS

**Step 12: Commit**

```bash
git add backend/services/validation/ backend/tests/services/validation/test_pre_validation_gates.py
git commit -m "feat(triage): implement pre-validation gates for cost optimization

Add PreValidationGates class that runs fast rule-based checks before expensive LLM validation:
- Gate 1: Disposition threshold filter
- Gate 2: Checklist quality (minimum PROVEN items)
- Gate 3: Social engineering detection

Returns ValidationResult if filtered, None if should proceed to LLM.

Comprehensive tests included for all gates."
```

---

## Task 3: Create LLM Validator Foundation

**Files:**
- Create: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for LLM validator initialization**

```python
# In backend/tests/services/validation/test_llm_validator.py

import pytest
from unittest.mock import Mock, patch
from services.validation.llm_validator import LLMFindingValidator


def test_llm_validator_initialization():
    """Test LLM validator can be initialized."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/test/repo",
        model="claude-sonnet-3-5-20241022"
    )

    assert validator.repo_root == "/test/repo"
    assert validator.model == "claude-sonnet-3-5-20241022"
    assert validator.tools is not None  # Tool implementations loaded


def test_llm_validator_default_model():
    """Test LLM validator uses default model if not specified."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/test/repo"
    )

    assert validator.model == "claude-sonnet-3-5-20241022"  # Default
```

**Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/services/validation/test_llm_validator.py::test_llm_validator_initialization -v
```

Expected: FAIL with "ImportError: cannot import name 'LLMFindingValidator'"

**Step 3: Create LLM validator stub**

```python
# In backend/services/validation/llm_validator.py

"""LLM-based finding validator with agentic tool use."""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class LLMFindingValidator:
    """
    Agentic LLM validator that uses tools to investigate findings.

    Validates reachability and attacker control with high skepticism.
    """

    def __init__(
        self,
        anthropic_api_key: str,
        repo_root: str,
        model: str = "claude-sonnet-3-5-20241022"
    ):
        """Initialize LLM validator."""
        try:
            from anthropic import Anthropic
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "LLMFindingValidator requires the 'anthropic' dependency. "
                "Install it or disable LLM validation."
            ) from exc

        self.client = Anthropic(api_key=anthropic_api_key)
        self.model = model
        self.repo_root = Path(repo_root)

        # Initialize tool implementations
        self.tools = {
            "read_file": self._tool_read_file,
            "grep_code": self._tool_grep_code,
            "glob_files": self._tool_glob_files,
        }

    def _tool_read_file(self, file_path: str) -> str:
        """Read file from repo (stub)."""
        return f"File content: {file_path}"

    def _tool_grep_code(self, pattern: str, glob: Optional[str] = None) -> str:
        """Grep codebase (stub)."""
        return f"Grep results for: {pattern}"

    def _tool_glob_files(self, pattern: str) -> str:
        """Glob files (stub)."""
        return f"Files matching: {pattern}"
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_llm_validator_initialization -v
pytest tests/services/validation/test_llm_validator.py::test_llm_validator_default_model -v
```

Expected: PASS (both tests)

**Step 5: Update validation __init__.py**

```python
# In backend/services/validation/__init__.py

"""Validation services for finding triage."""

from .pre_validation_gates import PreValidationGates
from .llm_validator import LLMFindingValidator

__all__ = ["PreValidationGates", "LLMFindingValidator"]
```

**Step 6: Write test for validation timeout**

```python
# In backend/tests/services/validation/test_llm_validator.py

import asyncio
import pytest
from models.schemas import Finding, Evidence, Severity, ValidationResult
from services.classification import ClassificationResult
from services.validation.llm_validator import LLMFindingValidator


@pytest.fixture
def mock_finding():
    return Finding(
        id="test-1",
        title="Command Injection",
        description="exec with user input",
        file_path="app.py",
        line_start=10,
        vulnerability_type="command_injection",
        severity=Severity.HIGH,
        code_snippet="exec(user_input)"
    )


@pytest.fixture
def mock_evidence():
    return Evidence(
        finding_id="test-1",
        snippet="exec(user_input)",
        matches=[],
        timed_out=False,
        input_channel="network",
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP endpoint"
    )


@pytest.fixture
def mock_classification():
    from models.schemas import ProofChecklist, ChecklistItem, ChecklistStatus, Disposition

    return ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=95,
        exploit_confidence=85,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            sink_present=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            dataflow_evidenced=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            reachable=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            boundary_crossed=ChecklistItem(True, ChecklistStatus.PROVEN, "test"),
            not_only_misconfig=ChecklistItem(True, ChecklistStatus.PROVEN, "test")
        ),
        reasoning=["Test"],
        category="command_injection"
    )


@pytest.mark.asyncio
async def test_validate_timeout(mock_finding, mock_evidence, mock_classification):
    """Test validator handles timeout gracefully."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    result = await validator.validate(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=None,
        criticism_level="high",
        timeout_seconds=0.001  # Force immediate timeout
    )

    assert isinstance(result, ValidationResult)
    assert result.is_valid == False
    assert "timeout" in result.categories
    assert "Validation timeout" in result.reasoning[0]
```

**Step 7: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_validate_timeout -v
```

Expected: FAIL with "AttributeError: 'LLMFindingValidator' object has no attribute 'validate'"

**Step 8: Implement validate method with timeout handling**

```python
# In backend/services/validation/llm_validator.py

import asyncio
from models.schemas import (
    Finding, Evidence, ValidationResult
)
from services.classification import ClassificationResult


class LLMFindingValidator:
    # ... existing __init__ and tool methods ...

    async def validate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str,
        timeout_seconds: int = 120
    ) -> ValidationResult:
        """
        Validate finding with timeout.

        Returns ValidationResult with is_valid flag and reasoning.
        """
        try:
            # Run validation with timeout
            result = await asyncio.wait_for(
                self._run_validation(
                    finding, evidence, classification,
                    threat_model_profile, criticism_level
                ),
                timeout=timeout_seconds
            )
            return result

        except asyncio.TimeoutError:
            # Timeout: default to INVALID (conservative)
            logger.warning(f"Validation timeout for finding {finding.id}")
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

    async def _run_validation(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str
    ) -> ValidationResult:
        """Run agentic validation (stub for now)."""
        # TODO: Implement agentic loop
        await asyncio.sleep(10)  # Simulate work
        return ValidationResult(
            is_valid=True,
            reasoning=["Stub implementation"],
            categories=["security_issue"]
        )
```

**Step 9: Run test to verify it passes**

```bash
pytest tests/services/validation/test_llm_validator.py::test_validate_timeout -v
```

Expected: PASS

**Step 10: Write test for error handling**

```python
# In backend/tests/services/validation/test_llm_validator.py

@pytest.mark.asyncio
async def test_validate_error_handling(mock_finding, mock_evidence, mock_classification, monkeypatch):
    """Test validator handles errors gracefully."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    # Mock _run_validation to raise exception
    async def mock_run_validation(*args, **kwargs):
        raise RuntimeError("Anthropic API error")

    monkeypatch.setattr(validator, "_run_validation", mock_run_validation)

    result = await validator.validate(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=None,
        criticism_level="high",
        timeout_seconds=10
    )

    assert isinstance(result, ValidationResult)
    assert result.is_valid == False
    assert "error" in result.categories
    assert "Validation error" in result.reasoning[0]
```

**Step 11: Run test to verify it passes**

```bash
pytest tests/services/validation/test_llm_validator.py::test_validate_error_handling -v
```

Expected: PASS

**Step 12: Run all validator tests**

```bash
pytest tests/services/validation/test_llm_validator.py -v
```

Expected: All tests PASS

**Step 13: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/services/validation/__init__.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): add LLM validator foundation with timeout/error handling

Add LLMFindingValidator class with:
- Anthropic client initialization
- Tool implementations stub (read_file, grep_code, glob_files)
- validate() method with timeout handling
- Error handling with conservative defaults (mark INVALID on error)
- Tests for initialization, timeout, and error handling

Agentic loop implementation deferred to next task."
```

---

## Task 4: Implement Validation Prompt Builder

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for prompt building**

```python
# In backend/tests/services/validation/test_llm_validator.py

def test_build_validation_prompt(mock_finding, mock_evidence, mock_classification):
    """Test validation prompt is built correctly."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    prompt = validator._build_validation_prompt(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=None,
        criticism_level="high"
    )

    assert isinstance(prompt, str)
    assert "Criticism Level: HIGH" in prompt
    assert mock_finding.title in prompt
    assert mock_finding.file_path in prompt
    assert "Task 1: Validate Attacker Control" in prompt
    assert "Task 2: Validate Reachability" in prompt
    assert "DECISION: VALID | INVALID" in prompt


def test_build_validation_prompt_medium_criticism(mock_finding, mock_evidence, mock_classification):
    """Test prompt with medium criticism level."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    prompt = validator._build_validation_prompt(
        finding=mock_finding,
        evidence=mock_evidence,
        classification=mock_classification,
        threat_model_profile=None,
        criticism_level="medium"
    )

    assert "Criticism Level: MEDIUM" in prompt
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_build_validation_prompt -v
```

Expected: FAIL with "AttributeError: 'LLMFindingValidator' object has no attribute '_build_validation_prompt'"

**Step 3: Implement _build_validation_prompt method**

```python
# In backend/services/validation/llm_validator.py

class LLMFindingValidator:
    # ... existing methods ...

    def _build_validation_prompt(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str
    ) -> str:
        """Build validation prompt with finding context."""

        # Format checklist items
        checklist = classification.proof_checklist
        checklist_text = f"""- Source Controlled Input: {checklist.source_controlled_input.status.value} - {checklist.source_controlled_input.reason}
- Sink Present: {checklist.sink_present.status.value} - {checklist.sink_present.reason}
- Dataflow Evidenced: {checklist.dataflow_evidenced.status.value} - {checklist.dataflow_evidenced.reason}
- Reachable: {checklist.reachable.status.value} - {checklist.reachable.reason}
- Boundary Crossed: {checklist.boundary_crossed.status.value} - {checklist.boundary_crossed.reason}
- Not Only Misconfig: {checklist.not_only_misconfig.status.value} - {checklist.not_only_misconfig.reason}"""

        return f"""You are a security validation expert performing secondary triage on a potential vulnerability.

## Your Mission
Determine if this is a TRUE EXPLOITABLE SECURITY ISSUE or should be filtered out.

## Criticism Level: {criticism_level.upper()}
HIGH: Assume NOT exploitable unless you can prove both reachability AND attacker control
MEDIUM: Accept strong evidence for one dimension, require proof for the other
LOW: Trust the initial classification unless clearly wrong

## Finding Summary
- Title: {finding.title}
- Type: {finding.vulnerability_type}
- File: {finding.file_path}:{finding.line_start}
- Disposition: {classification.disposition.value}
- Classification Confidence: {classification.classification_confidence}%

## Initial Classification Checklist
{checklist_text}

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
- read_file(file_path): Read source files
- grep_code(pattern, glob): Search codebase for patterns
- glob_files(pattern): Find files by name pattern

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

Be highly skeptical. Default to INVALID unless you can prove it's exploitable."""
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_build_validation_prompt -v
pytest tests/services/validation/test_llm_validator.py::test_build_validation_prompt_medium_criticism -v
```

Expected: PASS (both tests)

**Step 5: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): implement validation prompt builder

Add _build_validation_prompt() method that generates validation prompt with:
- Criticism level (HIGH/MEDIUM/LOW)
- Finding summary (title, type, file, disposition, confidence)
- Initial classification checklist with status and reasoning
- Investigation tasks (validate attacker control, reachability, categorize)
- Tool descriptions
- Output format specification

Tests verify prompt includes all required sections and adapts to criticism level."
```

---

## Task 5: Implement Tool Definitions for Anthropic API

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for tool definitions**

```python
# In backend/tests/services/validation/test_llm_validator.py

def test_get_tool_definitions():
    """Test tool definitions are formatted for Anthropic API."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    tools = validator._get_tool_definitions()

    assert isinstance(tools, list)
    assert len(tools) == 3

    # Check read_file tool
    read_tool = next(t for t in tools if t["name"] == "read_file")
    assert read_tool["description"] == "Read source file contents"
    assert "file_path" in read_tool["input_schema"]["properties"]
    assert "file_path" in read_tool["input_schema"]["required"]

    # Check grep_code tool
    grep_tool = next(t for t in tools if t["name"] == "grep_code")
    assert grep_tool["description"] == "Search codebase for patterns"
    assert "pattern" in grep_tool["input_schema"]["properties"]
    assert "glob" in grep_tool["input_schema"]["properties"]

    # Check glob_files tool
    glob_tool = next(t for t in tools if t["name"] == "glob_files")
    assert glob_tool["description"] == "Find files by name pattern"
    assert "pattern" in glob_tool["input_schema"]["properties"]
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_get_tool_definitions -v
```

Expected: FAIL with "AttributeError: 'LLMFindingValidator' object has no attribute '_get_tool_definitions'"

**Step 3: Implement _get_tool_definitions method**

```python
# In backend/services/validation/llm_validator.py

class LLMFindingValidator:
    # ... existing methods ...

    def _get_tool_definitions(self) -> list[dict]:
        """Get tool definitions for Anthropic API."""
        return [
            {
                "name": "read_file",
                "description": "Read source file contents",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to file relative to repo root"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "grep_code",
                "description": "Search codebase for patterns using regex",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern to search for"
                        },
                        "glob": {
                            "type": "string",
                            "description": "Optional glob pattern to filter files (e.g., '*.py')"
                        }
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "glob_files",
                "description": "Find files by name pattern",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern (e.g., '**/*.py', 'src/**/*test*.py')"
                        }
                    },
                    "required": ["pattern"]
                }
            }
        ]
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/validation/test_llm_validator.py::test_get_tool_definitions -v
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): add tool definitions for Anthropic API

Add _get_tool_definitions() method that returns tool schemas for:
- read_file: Read source files by path
- grep_code: Search codebase with regex pattern and optional glob filter
- glob_files: Find files by glob pattern

Tool definitions follow Anthropic API format with input_schema.

Test verifies all tools are defined with correct structure."
```

---

## Task 6: Implement Tool Execution Methods

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for read_file tool**

```python
# In backend/tests/services/validation/test_llm_validator.py

import tempfile
import os


def test_tool_read_file_success():
    """Test read_file tool reads file successfully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        test_file = os.path.join(tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("def vulnerable_function(user_input):\n    exec(user_input)\n")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("test.py")

        assert "def vulnerable_function" in result
        assert "exec(user_input)" in result


def test_tool_read_file_not_found():
    """Test read_file tool handles missing file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("nonexistent.py")

        assert "Error: File not found" in result


def test_tool_read_file_size_limit():
    """Test read_file tool respects size limit."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create large file
        test_file = os.path.join(tmpdir, "large.py")
        with open(test_file, "w") as f:
            f.write("x" * 200000)  # 200KB

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_read_file("large.py")

        # Should be truncated to 100KB
        assert len(result) <= 100000
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_tool_read_file_success -v
```

Expected: FAIL (reads stub implementation, not actual file)

**Step 3: Implement _tool_read_file method**

```python
# In backend/services/validation/llm_validator.py

class LLMFindingValidator:
    # ... existing methods ...

    def _tool_read_file(self, file_path: str) -> str:
        """Read file from repo."""
        full_path = self.repo_root / file_path

        if not full_path.exists():
            return f"Error: File not found: {file_path}"

        if not full_path.is_file():
            return f"Error: Not a file: {file_path}"

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100000)  # Limit to 100KB
            return content
        except Exception as e:
            return f"Error reading file: {str(e)}"
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_tool_read_file_success -v
pytest tests/services/validation/test_llm_validator.py::test_tool_read_file_not_found -v
pytest tests/services/validation/test_llm_validator.py::test_tool_read_file_size_limit -v
```

Expected: PASS (all three tests)

**Step 5: Write test for grep_code tool**

```python
# In backend/tests/services/validation/test_llm_validator.py

def test_tool_grep_code_basic():
    """Test grep_code tool finds pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_file1 = os.path.join(tmpdir, "app.py")
        with open(test_file1, "w") as f:
            f.write("def handler():\n    exec(user_input)\n")

        test_file2 = os.path.join(tmpdir, "utils.py")
        with open(test_file2, "w") as f:
            f.write("def helper():\n    print('safe')\n")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_grep_code("exec")

        assert "app.py" in result
        assert "exec(user_input)" in result
        assert "utils.py" not in result


def test_tool_grep_code_with_glob():
    """Test grep_code tool with glob filter."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_py = os.path.join(tmpdir, "test.py")
        with open(test_py, "w") as f:
            f.write("exec(cmd)")

        test_js = os.path.join(tmpdir, "test.js")
        with open(test_js, "w") as f:
            f.write("exec(cmd)")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_grep_code("exec", glob="*.py")

        assert "test.py" in result
        assert "test.js" not in result
```

**Step 6: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_tool_grep_code_basic -v
```

Expected: FAIL (stub returns generic message)

**Step 7: Implement _tool_grep_code method**

```python
# In backend/services/validation/llm_validator.py

import subprocess


class LLMFindingValidator:
    # ... existing methods ...

    def _tool_grep_code(self, pattern: str, glob: Optional[str] = None) -> str:
        """Grep codebase using ripgrep."""
        try:
            cmd = ["rg", "--no-heading", "--line-number", pattern, str(self.repo_root)]

            if glob:
                cmd.extend(["--glob", glob])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Limit output to 5000 chars
                return result.stdout[:5000]
            elif result.returncode == 1:
                return f"No matches found for pattern: {pattern}"
            else:
                return f"Grep error: {result.stderr[:500]}"

        except subprocess.TimeoutExpired:
            return "Grep timeout - pattern may be too broad"
        except FileNotFoundError:
            return "Error: ripgrep (rg) not found - install ripgrep"
        except Exception as e:
            return f"Grep error: {str(e)}"
```

**Step 8: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_tool_grep_code_basic -v
pytest tests/services/validation/test_llm_validator.py::test_tool_grep_code_with_glob -v
```

Expected: PASS (both tests) - or SKIP if ripgrep not installed

**Step 9: Write test for glob_files tool**

```python
# In backend/tests/services/validation/test_llm_validator.py

def test_tool_glob_files():
    """Test glob_files tool finds files by pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create directory structure
        os.makedirs(os.path.join(tmpdir, "src"))
        os.makedirs(os.path.join(tmpdir, "tests"))

        # Create files
        open(os.path.join(tmpdir, "src", "app.py"), "w").close()
        open(os.path.join(tmpdir, "src", "utils.py"), "w").close()
        open(os.path.join(tmpdir, "tests", "test_app.py"), "w").close()

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_glob_files("**/*.py")

        assert "src/app.py" in result or "src\\app.py" in result  # Windows path
        assert "src/utils.py" in result or "src\\utils.py" in result
        assert "test_app.py" in result


def test_tool_glob_files_specific_pattern():
    """Test glob_files with specific pattern."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "tests"))

        open(os.path.join(tmpdir, "app.py"), "w").close()
        open(os.path.join(tmpdir, "tests", "test_app.py"), "w").close()

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        result = validator._tool_glob_files("**/test_*.py")

        assert "test_app.py" in result
        assert "app.py" not in result
```

**Step 10: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_tool_glob_files -v
```

Expected: FAIL (stub returns generic message)

**Step 11: Implement _tool_glob_files method**

```python
# In backend/services/validation/llm_validator.py

import glob as glob_module


class LLMFindingValidator:
    # ... existing methods ...

    def _tool_glob_files(self, pattern: str) -> str:
        """Glob files by pattern."""
        try:
            # Use glob.glob with recursive=True
            matches = glob_module.glob(
                str(self.repo_root / pattern),
                recursive=True
            )

            # Convert to relative paths
            relative_matches = []
            for match in matches:
                try:
                    rel = Path(match).relative_to(self.repo_root)
                    relative_matches.append(str(rel))
                except ValueError:
                    continue

            if not relative_matches:
                return f"No files found matching: {pattern}"

            # Limit to 100 files
            if len(relative_matches) > 100:
                relative_matches = relative_matches[:100]
                return "\\n".join(relative_matches) + f"\\n... ({len(matches) - 100} more files)"

            return "\\n".join(relative_matches)

        except Exception as e:
            return f"Glob error: {str(e)}"
```

**Step 12: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_tool_glob_files -v
pytest tests/services/validation/test_llm_validator.py::test_tool_glob_files_specific_pattern -v
```

Expected: PASS (both tests)

**Step 13: Run all tool tests**

```bash
pytest tests/services/validation/test_llm_validator.py -k "tool_" -v
```

Expected: All tool tests PASS

**Step 14: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): implement tool execution methods for LLM validator

Implement tool methods for agentic investigation:
- _tool_read_file: Read files from repo with 100KB size limit, error handling
- _tool_grep_code: Search codebase using ripgrep with optional glob filter, 5000 char limit
- _tool_glob_files: Find files by glob pattern, limit to 100 files

All tools have comprehensive error handling and resource limits.

Tests verify successful execution, error cases, and resource limits."
```

---

## Task 7: Implement Agentic Loop (Part 1 - Tool Execution)

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for tool execution in agentic loop**

```python
# In backend/tests/services/validation/test_llm_validator.py

from unittest.mock import Mock, AsyncMock, patch


@pytest.mark.asyncio
async def test_execute_tool_call_read_file():
    """Test executing read_file tool call."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.py")
        with open(test_file, "w") as f:
            f.write("exec(cmd)")

        validator = LLMFindingValidator(
            anthropic_api_key="test-key",
            repo_root=tmpdir
        )

        tool_use = Mock()
        tool_use.name = "read_file"
        tool_use.input = {"file_path": "test.py"}
        tool_use.id = "tool_123"

        result = await validator._execute_tool_call(tool_use)

        assert result["type"] == "tool_result"
        assert result["tool_use_id"] == "tool_123"
        assert "exec(cmd)" in result["content"]


@pytest.mark.asyncio
async def test_execute_tool_call_unknown_tool():
    """Test executing unknown tool returns error."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    tool_use = Mock()
    tool_use.name = "unknown_tool"
    tool_use.input = {}
    tool_use.id = "tool_123"

    result = await validator._execute_tool_call(tool_use)

    assert result["type"] == "tool_result"
    assert "Unknown tool" in result["content"]
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_execute_tool_call_read_file -v
```

Expected: FAIL with "AttributeError: 'LLMFindingValidator' object has no attribute '_execute_tool_call'"

**Step 3: Implement _execute_tool_call method**

```python
# In backend/services/validation/llm_validator.py

class LLMFindingValidator:
    # ... existing methods ...

    async def _execute_tool_call(self, tool_use) -> dict:
        """Execute a single tool call and return result."""
        tool_name = tool_use.name
        tool_input = tool_use.input
        tool_id = tool_use.id

        try:
            if tool_name not in self.tools:
                return {
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": f"Unknown tool: {tool_name}"
                }

            # Get tool function
            tool_fn = self.tools[tool_name]

            # Execute tool (synchronous)
            result = tool_fn(**tool_input)

            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": result
            }

        except Exception as e:
            logger.error(f"Tool execution error ({tool_name}): {e}")
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": f"Tool error: {str(e)}"
            }
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_execute_tool_call_read_file -v
pytest tests/services/validation/test_llm_validator.py::test_execute_tool_call_unknown_tool -v
```

Expected: PASS (both tests)

**Step 5: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): add tool execution for agentic loop

Add _execute_tool_call() method that:
- Routes tool calls to appropriate tool implementation
- Handles unknown tools gracefully
- Catches and reports tool execution errors
- Returns tool_result dict in Anthropic API format

Tests verify tool routing, error handling, and result format."
```

---

## Task 8: Implement Agentic Loop (Part 2 - Response Parsing)

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for response parsing**

```python
# In backend/tests/services/validation/test_llm_validator.py

def test_parse_validation_response_valid():
    """Test parsing VALID decision from LLM response."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    response_text = """DECISION: VALID
CATEGORY: security_issue
REASONING:
- exec() is reachable from HTTP endpoint /api/run
- User input flows directly to exec without sanitization
- Clear path from untrusted source to dangerous sink"""

    result = validator._parse_validation_response(response_text)

    assert isinstance(result, ValidationResult)
    assert result.is_valid == True
    assert result.categories == ["security_issue"]
    assert len(result.reasoning) == 3
    assert "exec() is reachable" in result.reasoning[0]


def test_parse_validation_response_invalid():
    """Test parsing INVALID decision from LLM response."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    response_text = """DECISION: INVALID
CATEGORY: hardening
REASONING:
- exec() function exists but is never called
- No route registration found
- Function appears to be dead code"""

    result = validator._parse_validation_response(response_text)

    assert isinstance(result, ValidationResult)
    assert result.is_valid == False
    assert result.categories == ["hardening"]
    assert len(result.reasoning) == 3


def test_parse_validation_response_malformed():
    """Test parsing malformed response defaults to INVALID."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    response_text = "This is not a valid response format"

    result = validator._parse_validation_response(response_text)

    assert isinstance(result, ValidationResult)
    assert result.is_valid == False
    assert "parse" in result.categories[0].lower()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_parse_validation_response_valid -v
```

Expected: FAIL with "AttributeError: 'LLMFindingValidator' object has no attribute '_parse_validation_response'"

**Step 3: Implement _parse_validation_response method**

```python
# In backend/services/validation/llm_validator.py

import re


class LLMFindingValidator:
    # ... existing methods ...

    def _parse_validation_response(self, response_text: str) -> ValidationResult:
        """Parse validation response from LLM."""
        try:
            # Extract DECISION
            decision_match = re.search(r"DECISION:\s*(VALID|INVALID)", response_text, re.IGNORECASE)
            if not decision_match:
                raise ValueError("No DECISION found in response")

            is_valid = decision_match.group(1).upper() == "VALID"

            # Extract CATEGORY
            category_match = re.search(
                r"CATEGORY:\s*(\w+(?:_\w+)*)",
                response_text,
                re.IGNORECASE
            )
            category = category_match.group(1) if category_match else "unknown"

            # Extract REASONING bullets
            reasoning_section = re.search(
                r"REASONING:\s*((?:^-.*$\n?)+)",
                response_text,
                re.MULTILINE | re.IGNORECASE
            )

            if reasoning_section:
                reasoning_text = reasoning_section.group(1)
                reasoning = [
                    line.strip("- ").strip()
                    for line in reasoning_text.split("\n")
                    if line.strip().startswith("-")
                ]
            else:
                reasoning = ["No reasoning provided"]

            return ValidationResult(
                is_valid=is_valid,
                reasoning=reasoning,
                categories=[category]
            )

        except Exception as e:
            logger.error(f"Failed to parse validation response: {e}")
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    "Failed to parse validator response",
                    f"Parse error: {str(e)[:200]}"
                ],
                categories=["parse_error"]
            )
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_parse_validation_response_valid -v
pytest tests/services/validation/test_llm_validator.py::test_parse_validation_response_invalid -v
pytest tests/services/validation/test_llm_validator.py::test_parse_validation_response_malformed -v
```

Expected: PASS (all three tests)

**Step 5: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): add validation response parser

Add _parse_validation_response() method that:
- Extracts DECISION (VALID/INVALID) using regex
- Extracts CATEGORY (security_issue, bug, hardening, etc.)
- Extracts REASONING bullets from response
- Handles malformed responses gracefully (defaults to INVALID)

Tests verify parsing of valid/invalid decisions and error handling."
```

---

## Task 9: Implement Agentic Loop (Part 3 - Main Loop)

**Files:**
- Modify: `backend/services/validation/llm_validator.py`
- Test: `backend/tests/services/validation/test_llm_validator.py`

**Step 1: Write test for agentic validation loop**

```python
# In backend/tests/services/validation/test_llm_validator.py

@pytest.mark.asyncio
async def test_run_validation_with_tool_use(mock_finding, mock_evidence, mock_classification, monkeypatch):
    """Test agentic loop with tool use."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    # Mock Anthropic API responses
    call_count = [0]

    class MockMessage:
        def __init__(self, stop_reason, content):
            self.stop_reason = stop_reason
            self.content = content

    class MockToolUse:
        def __init__(self):
            self.type = "tool_use"
            self.name = "read_file"
            self.input = {"file_path": "test.py"}
            self.id = "tool_123"

    class MockTextBlock:
        def __init__(self, text):
            self.type = "text"
            self.text = text

    async def mock_create(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            # First call: return tool_use
            return MockMessage("tool_use", [MockToolUse()])
        else:
            # Second call: return final decision
            return MockMessage("end_turn", [MockTextBlock("""DECISION: VALID
CATEGORY: security_issue
REASONING:
- Finding is exploitable
- Confirmed via code inspection""")])

    # Mock client.messages.create
    mock_client = Mock()
    mock_client.messages.create = mock_create
    validator.client = mock_client

    result = await validator._run_validation(
        mock_finding, mock_evidence, mock_classification, None, "high"
    )

    assert isinstance(result, ValidationResult)
    assert call_count[0] == 2  # Two API calls


@pytest.mark.asyncio
async def test_run_validation_max_turns(mock_finding, mock_evidence, mock_classification, monkeypatch):
    """Test agentic loop respects max turns limit."""
    validator = LLMFindingValidator(
        anthropic_api_key="test-key",
        repo_root="/tmp"
    )

    class MockMessage:
        def __init__(self):
            self.stop_reason = "tool_use"
            self.content = []

    async def mock_create(*args, **kwargs):
        return MockMessage()  # Always return tool_use, never finish

    mock_client = Mock()
    mock_client.messages.create = mock_create
    validator.client = mock_client

    result = await validator._run_validation(
        mock_finding, mock_evidence, mock_classification, None, "high"
    )

    # Should return INVALID when max turns exceeded
    assert isinstance(result, ValidationResult)
    assert result.is_valid == False
    assert any("exceeded" in r.lower() for r in result.reasoning)
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/validation/test_llm_validator.py::test_run_validation_with_tool_use -v
```

Expected: FAIL (_run_validation is still a stub)

**Step 3: Implement _run_validation main loop**

```python
# In backend/services/validation/llm_validator.py

class LLMFindingValidator:
    # ... existing methods ...

    async def _run_validation(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str
    ) -> ValidationResult:
        """Run agentic validation with tool use."""

        # Build system prompt
        system_prompt = self._build_validation_prompt(
            finding, evidence, classification,
            threat_model_profile, criticism_level
        )

        # Get tool definitions
        tools = self._get_tool_definitions()

        # Initialize conversation
        messages = [{"role": "user", "content": "Begin investigation."}]

        max_turns = 10
        investigation_steps = []

        for turn in range(max_turns):
            try:
                # Call Anthropic API
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=system_prompt,
                    messages=messages,
                    tools=tools
                )

                # Check stop reason
                if response.stop_reason == "end_turn":
                    # Extract final decision from text block
                    for block in response.content:
                        if hasattr(block, 'text'):
                            return self._parse_validation_response(block.text)

                    # No text block found
                    return ValidationResult(
                        is_valid=False,
                        reasoning=["No decision in final response"],
                        categories=["parse_error"]
                    )

                elif response.stop_reason == "tool_use":
                    # Execute tool calls
                    tool_results = []
                    for block in response.content:
                        if hasattr(block, 'type') and block.type == "tool_use":
                            investigation_steps.append(f"{block.name}({block.input})")
                            result = await self._execute_tool_call(block)
                            tool_results.append(result)

                    # Add assistant response + tool results to conversation
                    messages.append({
                        "role": "assistant",
                        "content": response.content
                    })
                    messages.append({
                        "role": "user",
                        "content": tool_results
                    })

                else:
                    # Unexpected stop reason
                    logger.warning(f"Unexpected stop_reason: {response.stop_reason}")
                    return ValidationResult(
                        is_valid=False,
                        reasoning=[f"Unexpected stop reason: {response.stop_reason}"],
                        categories=["error"]
                    )

            except Exception as e:
                logger.error(f"Error in validation turn {turn}: {e}")
                raise  # Will be caught by validate() method

        # Max turns exceeded
        return ValidationResult(
            is_valid=False,
            reasoning=[
                f"Investigation exceeded maximum {max_turns} tool use rounds",
                "Could not reach conclusion - filtered conservatively"
            ],
            categories=["inconclusive"],
            investigation_steps=investigation_steps
        )
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/services/validation/test_llm_validator.py::test_run_validation_with_tool_use -v
pytest tests/services/validation/test_llm_validator.py::test_run_validation_max_turns -v
```

Expected: PASS (both tests)

**Step 5: Run all LLM validator tests**

```bash
pytest tests/services/validation/test_llm_validator.py -v
```

Expected: All tests PASS

**Step 6: Commit**

```bash
git add backend/services/validation/llm_validator.py backend/tests/services/validation/test_llm_validator.py
git commit -m "feat(triage): implement agentic validation loop

Add _run_validation() method that:
- Builds validation prompt and tool definitions
- Runs agentic loop (max 10 turns)
- Executes tool calls as needed
- Parses final decision
- Tracks investigation steps
- Handles max turns exceeded

Complete LLM validator implementation with full agentic capabilities.

Tests verify tool use flow and max turns limit."
```

---

## Task 10: Wire LLM Validator into Triage Pipeline

**Files:**
- Modify: `backend/services/finding_triage_service.py`
- Test: `backend/tests/integration/test_llm_validation_pipeline.py`

**Step 1: Write integration test for pipeline with validation**

```python
# In backend/tests/integration/test_llm_validation_pipeline.py

import pytest
from models.schemas import (
    Finding, Severity, BudgetConfig, ProtocolPolicy, Disposition
)
from services.finding_triage_service import FindingTriageService


@pytest.fixture
def sample_finding():
    return Finding(
        id="test-1",
        title="Command Injection in API",
        description="exec() with user input",
        file_path="api/handler.py",
        line_start=42,
        vulnerability_type="command_injection",
        severity=Severity.HIGH,
        code_snippet="exec(request.args.get('cmd'))"
    )


@pytest.fixture
def validation_enabled_policy():
    return ProtocolPolicy(
        id="test-policy",
        display_name="Test Policy",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE, Disposition.BUG],
        min_checklist_proven_count=4,
        enable_llm_validation=True,
        validation_criticism_level="high",
        validation_timeout_seconds=60
    )


@pytest.fixture
def validation_disabled_policy():
    return ProtocolPolicy(
        id="test-policy",
        display_name="Test Policy",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE, Disposition.BUG],
        min_checklist_proven_count=4,
        enable_llm_validation=False
    )


@pytest.mark.asyncio
async def test_pipeline_with_llm_validation_enabled(
    sample_finding,
    validation_enabled_policy,
    tmp_path
):
    """Test triage pipeline with LLM validation enabled."""
    service = FindingTriageService()

    # Mock ANTHROPIC_API_KEY for this test
    import os
    os.environ["ANTHROPIC_API_KEY"] = "test-key"

    result = await service.triage_with_protocol(
        repo_root=str(tmp_path),
        findings=[sample_finding],
        protocol_policy=validation_enabled_policy,
        budgets=BudgetConfig()
    )

    assert len(result.triaged_findings) == 1
    triaged = result.triaged_findings[0]

    # Should have validation_result
    assert triaged.validation_result is not None
    assert isinstance(triaged.validation_result.is_valid, bool)
    assert len(triaged.validation_result.reasoning) > 0

    # Should have submission_result (backward compat)
    assert triaged.submission_result is not None


@pytest.mark.asyncio
async def test_pipeline_with_validation_disabled(
    sample_finding,
    validation_disabled_policy,
    tmp_path
):
    """Test triage pipeline with LLM validation disabled."""
    service = FindingTriageService()

    result = await service.triage_with_protocol(
        repo_root=str(tmp_path),
        findings=[sample_finding],
        protocol_policy=validation_disabled_policy,
        budgets=BudgetConfig()
    )

    assert len(result.triaged_findings) == 1
    triaged = result.triaged_findings[0]

    # Should have validation_result (auto-approved)
    assert triaged.validation_result is not None
    assert triaged.validation_result.is_valid == True
    assert "disabled" in triaged.validation_result.reasoning[0].lower()
```

**Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/integration/test_llm_validation_pipeline.py::test_pipeline_with_llm_validation_enabled -v
```

Expected: FAIL (pipeline doesn't use validator yet)

**Step 3: Wire validator into triage_with_protocol**

```python
# In backend/services/finding_triage_service.py

# Add imports at top
from services.validation import PreValidationGates, LLMFindingValidator

class FindingTriageService:
    def __init__(self):
        # ... existing initialization ...
        self.pre_validation_gates = PreValidationGates()
        self.llm_validator: Optional[LLMFindingValidator] = None

    async def triage_with_protocol(
        self,
        repo_root: str,
        findings: list[Finding],
        policy_version: str = "1.0.0",
        budgets: Optional[BudgetConfig] = None,
        threat_model_profile: Optional[dict] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        db_conn = None,
    ) -> TriageResult:
        # ... existing code until line 277 ...

        # Initialize LLM validator if enabled
        if protocol_policy and protocol_policy.enable_llm_validation:
            api_key = ProtocolConfig.ANTHROPIC_API_KEY
            if api_key:
                self.llm_validator = LLMFindingValidator(
                    anthropic_api_key=api_key,
                    repo_root=repo_root,
                    model=protocol_policy.validation_model or "claude-sonnet-3-5-20241022"
                )
            else:
                print("⚠️  Warning: No ANTHROPIC_API_KEY - LLM validation disabled")

        # ... existing loop code ...

        # After Step 2: Classification (around line 372-375)
        # Add Step 3: Validation

        # Step 3: Validation
        if protocol_policy:
            # Step 3a: Pre-validation gates (fast rule checks)
            gate_result = self.pre_validation_gates.check_gates(
                finding, evidence, classification, protocol_policy
            )

            if gate_result and not gate_result.is_valid:
                # Failed gates - filtered without LLM validation
                validation_result = gate_result
            elif protocol_policy.enable_llm_validation and self.llm_validator:
                # Step 3b: Deep LLM Validator (agentic investigation)
                validation_result = await self.llm_validator.validate(
                    finding=finding,
                    evidence=evidence,
                    classification=classification,
                    threat_model_profile=threat_model_profile,
                    criticism_level=protocol_policy.validation_criticism_level or "high",
                    timeout_seconds=protocol_policy.validation_timeout_seconds
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
        else:
            finding.validation_result = None
            finding.submission_result = None

        # ... rest of existing code (attach metadata, track reportable) ...

        # Track reportable based on validation
        if finding.validation_result and finding.validation_result.is_valid:
            reportable.append(triaged_finding)
        elif not protocol_policy:
            # Fallback to disposition if no protocol
            if classification.disposition in [
                Disposition.VALID_SECURITY_ISSUE,
                Disposition.BUG
            ]:
                reportable.append(triaged_finding)
```

**Step 4: Add helper method _validation_to_submission_result**

```python
# In backend/services/finding_triage_service.py

class FindingTriageService:
    # ... existing methods ...

    def _validation_to_submission_result(
        self,
        validation_result: ValidationResult,
        protocol_policy: ProtocolPolicy
    ) -> SubmissionResult:
        """Convert ValidationResult to SubmissionResult for backward compatibility."""
        if validation_result.is_valid:
            return SubmissionResult(
                protocol_id=protocol_policy.id,
                decision=SubmissionDecision.SUBMIT,
                reasons=validation_result.reasoning,
                missing_evidence=[],
                suggested_next_steps=[]
            )
        else:
            return SubmissionResult(
                protocol_id=protocol_policy.id,
                decision=SubmissionDecision.DONT_SUBMIT,
                reasons=validation_result.reasoning,
                missing_evidence=[],
                suggested_next_steps=[]
            )
```

**Step 5: Run tests to verify they pass**

```bash
pytest tests/integration/test_llm_validation_pipeline.py::test_pipeline_with_llm_validation_enabled -v
pytest tests/integration/test_llm_validation_pipeline.py::test_pipeline_with_validation_disabled -v
```

Expected: PASS (both tests) - may need to mock Anthropic API calls

**Step 6: Commit**

```bash
git add backend/services/finding_triage_service.py backend/tests/integration/test_llm_validation_pipeline.py
git commit -m "feat(triage): wire LLM validator into triage pipeline

Integrate LLM validator into triage_with_protocol:
- Initialize validator if enable_llm_validation=True
- Run pre-validation gates first (fast rule checks)
- Run LLM validator for findings that pass gates
- Auto-approve if validation disabled
- Store validation_result on finding
- Convert to SubmissionResult for backward compatibility
- Track reportable based on validation result

Integration tests verify pipeline with validation enabled/disabled."
```

---

## Task 11: Add Frontend Types

**Files:**
- Modify: `frontend/types/protocol.ts`

**Step 1: Add ValidationResult type**

```typescript
// In frontend/types/protocol.ts

export interface ValidationResult {
  is_valid: boolean;
  reasoning: string[];
  categories: string[];
  investigation_steps?: string[];
  confidence?: number;
  timestamp: string;
}
```

**Step 2: Update Finding type to include validation_result**

```typescript
// In frontend/types/protocol.ts (or frontend/types/index.ts)

export interface Finding {
  // ... existing fields ...
  submission_result?: SubmissionResult;
  validation_result?: ValidationResult;  // NEW
}
```

**Step 3: Commit**

```bash
git add frontend/types/protocol.ts
git commit -m "feat(frontend): add ValidationResult type

Add ValidationResult interface with:
- is_valid: boolean flag
- reasoning: array of explanation bullets
- categories: classification categories
- investigation_steps: optional tool calls made
- confidence: optional 0-100 score
- timestamp: validation timestamp

Update Finding type to include optional validation_result field."
```

---

## Task 12: Implement Report Toggle UI

**Files:**
- Modify: `frontend/components/FindingsReportView.tsx`
- Modify: `frontend/components/FindingDrawer/SubmissionPanel.tsx`

**Step 1: Add filter toggle to FindingsReportView**

```typescript
// In frontend/components/FindingsReportView.tsx

import { useState, useMemo } from 'react';

export function FindingsReportView({ findings }: { findings: Finding[] }) {
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

  const filteredCount = findings.length - displayedFindings.length;

  return (
    <div className="findings-report">
      {/* Filter toggle */}
      <div className="filter-toggle mb-4 p-3 bg-vsc-input rounded">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={showFiltered}
            onChange={(e) => setShowFiltered(e.target.checked)}
            className="w-4 h-4"
          />
          <span className="text-sm">Show only validated findings</span>
        </label>
        <span className="text-xs text-vsc-descriptionForeground mt-1 block">
          {showFiltered
            ? `Showing ${displayedFindings.length} validated findings`
            : `Showing all ${displayedFindings.length} findings (${filteredCount} filtered by validator)`
          }
        </span>
      </div>

      {/* Findings list */}
      <div className="findings-list">
        {displayedFindings.map(finding => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </div>
  );
}
```

**Step 2: Add validation badge to FindingCard/SubmissionPanel**

```typescript
// In frontend/components/FindingDrawer/SubmissionPanel.tsx

export function SubmissionPanel({ finding }: { finding: Finding }) {
  return (
    <div className="submission-panel">
      {/* Existing submission result display */}
      {finding.submission_result && (
        <div className="submission-result">
          {/* ... existing code ... */}
        </div>
      )}

      {/* NEW: Validation result display */}
      {finding.validation_result && (
        <div className="validation-result mt-4">
          <h4 className="text-sm font-semibold mb-2">LLM Validation</h4>

          {/* Validation badge */}
          <div className={`inline-flex items-center gap-2 px-3 py-1 rounded text-sm ${
            finding.validation_result.is_valid
              ? 'bg-green-900/30 text-green-400 border border-green-700'
              : 'bg-red-900/30 text-red-400 border border-red-700'
          }`}>
            {finding.validation_result.is_valid ? (
              <>
                <span className="text-lg">✓</span>
                <span>Validated</span>
              </>
            ) : (
              <>
                <span className="text-lg">✗</span>
                <span>Filtered</span>
              </>
            )}
          </div>

          {/* Category */}
          {finding.validation_result.categories.length > 0 && (
            <div className="mt-2 text-xs">
              <span className="text-vsc-descriptionForeground">Category: </span>
              <span className="text-vsc-foreground">
                {finding.validation_result.categories.join(', ')}
              </span>
            </div>
          )}

          {/* Reasoning */}
          <div className="mt-3">
            <h5 className="text-xs font-semibold text-vsc-descriptionForeground mb-1">
              Reasoning:
            </h5>
            <ul className="text-xs space-y-1">
              {finding.validation_result.reasoning.map((reason, idx) => (
                <li key={idx} className="text-vsc-foreground">
                  • {reason}
                </li>
              ))}
            </ul>
          </div>

          {/* Investigation steps (if available) */}
          {finding.validation_result.investigation_steps && (
            <div className="mt-3">
              <h5 className="text-xs font-semibold text-vsc-descriptionForeground mb-1">
                Investigation:
              </h5>
              <ul className="text-xs space-y-1">
                {finding.validation_result.investigation_steps.map((step, idx) => (
                  <li key={idx} className="text-vsc-descriptionForeground font-mono">
                    {step}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
```

**Step 3: Test UI manually**

```bash
cd frontend
npm run dev
```

Manual test:
1. Navigate to findings report
2. Verify toggle appears
3. Toggle on: only validated findings shown
4. Toggle off: all findings shown with validation badges
5. Click finding: verify validation result displayed in drawer

**Step 4: Commit**

```bash
git add frontend/components/FindingsReportView.tsx frontend/components/FindingDrawer/SubmissionPanel.tsx
git commit -m "feat(frontend): implement report toggle for LLM validation

Add filter toggle to FindingsReportView:
- Checkbox to show only validated findings
- Count display (validated vs total)
- Defaults to filtered view
- Backward compatible (treats missing validation_result as validated)

Add validation result display to SubmissionPanel:
- Validation badge (✓ Validated or ✗ Filtered)
- Category display
- Reasoning bullets
- Investigation steps (if available)

Manual testing required for UI verification."
```

---

## Task 13: Integration Tests

**Files:**
- Create: `backend/tests/integration/test_validation_end_to_end.py`

**Step 1: Write end-to-end test with real file operations**

```python
# In backend/tests/integration/test_validation_end_to_end.py

import pytest
import tempfile
import os
from pathlib import Path
from models.schemas import (
    Finding, Severity, ProtocolPolicy, Disposition
)
from services.finding_triage_service import FindingTriageService


@pytest.fixture
def test_repo_with_vulnerability():
    """Create temporary repo with vulnerable code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create vulnerable file
        vuln_file = Path(tmpdir) / "api" / "handler.py"
        vuln_file.parent.mkdir(parents=True, exist_ok=True)
        vuln_file.write_text("""
from flask import Flask, request

app = Flask(__name__)

@app.route('/run')
def run_command():
    cmd = request.args.get('cmd')
    exec(cmd)  # Vulnerable line
    return 'Done'
""")

        # Create entry point
        main_file = Path(tmpdir) / "main.py"
        main_file.write_text("""
from api.handler import app

if __name__ == '__main__':
    app.run()
""")

        yield tmpdir


@pytest.fixture
def test_repo_with_safe_code():
    """Create temporary repo with safe code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create safe file
        safe_file = Path(tmpdir) / "utils.py"
        safe_file.write_text("""
def helper_function():
    # This looks dangerous but is never called
    def unused():
        exec("print('test')")

    print('Safe operation')
""")

        yield tmpdir


@pytest.mark.asyncio
@pytest.mark.integration
async def test_validation_rejects_unreachable_exec(test_repo_with_safe_code):
    """Test LLM validator rejects unreachable exec()."""
    service = FindingTriageService()

    finding = Finding(
        id="test-1",
        title="exec() in unused function",
        description="exec() found but function is never called",
        file_path="utils.py",
        line_start=5,
        vulnerability_type="command_injection",
        severity=Severity.HIGH,
        code_snippet="exec(\"print('test')\")"
    )

    policy = ProtocolPolicy(
        id="test",
        display_name="Test",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE],
        min_checklist_proven_count=4,
        enable_llm_validation=True,
        validation_criticism_level="high",
        validation_timeout_seconds=60
    )

    # Set API key
    os.environ["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY", "test-key")

    result = await service.triage_with_protocol(
        repo_root=test_repo_with_safe_code,
        findings=[finding],
        protocol_policy=policy
    )

    assert len(result.triaged_findings) == 1
    triaged = result.triaged_findings[0]

    # Should be marked INVALID by validator
    assert triaged.validation_result is not None
    assert triaged.validation_result.is_valid == False
    assert any("not reachable" in r.lower() or "not called" in r.lower()
               for r in triaged.validation_result.reasoning)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_validation_accepts_reachable_exec(test_repo_with_vulnerability):
    """Test LLM validator accepts reachable exec()."""
    service = FindingTriageService()

    finding = Finding(
        id="test-1",
        title="exec() in HTTP handler",
        description="exec() with user input in Flask route",
        file_path="api/handler.py",
        line_start=8,
        vulnerability_type="command_injection",
        severity=Severity.HIGH,
        code_snippet="exec(cmd)"
    )

    policy = ProtocolPolicy(
        id="test",
        display_name="Test",
        min_disposition_to_submit=[Disposition.VALID_SECURITY_ISSUE],
        min_checklist_proven_count=4,
        enable_llm_validation=True,
        validation_criticism_level="high",
        validation_timeout_seconds=60
    )

    os.environ["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY", "test-key")

    result = await service.triage_with_protocol(
        repo_root=test_repo_with_vulnerability,
        findings=[finding],
        protocol_policy=policy
    )

    assert len(result.triaged_findings) == 1
    triaged = result.triaged_findings[0]

    # Should be marked VALID by validator
    assert triaged.validation_result is not None
    assert triaged.validation_result.is_valid == True
    assert any("reachable" in r.lower() or "http" in r.lower()
               for r in triaged.validation_result.reasoning)
```

**Step 2: Run integration tests**

```bash
# Requires ANTHROPIC_API_KEY environment variable
export ANTHROPIC_API_KEY=your-key-here
pytest tests/integration/test_validation_end_to_end.py -v -m integration
```

Expected: PASS (both tests) - requires real API key

**Step 3: Commit**

```bash
git add backend/tests/integration/test_validation_end_to_end.py
git commit -m "test(triage): add end-to-end validation integration tests

Add integration tests that:
- Create temporary repos with vulnerable/safe code
- Run full triage pipeline with LLM validation
- Verify validator correctly identifies reachable vs unreachable vulnerabilities

Tests require ANTHROPIC_API_KEY environment variable.

Mark with @pytest.mark.integration to skip in CI without API key."
```

---

## Task 14: Manual Testing & Documentation

**Files:**
- Create: `docs/LLM_VALIDATION_GUIDE.md`

**Step 1: Create user guide**

```markdown
# LLM Validation User Guide

## Overview

The LLM validation layer uses agentic AI to deeply validate security findings by investigating code reachability and attacker control with high skepticism.

## Configuration

### Enable/Disable Validation

```python
protocol_policy = ProtocolPolicy(
    id="my-policy",
    display_name="My Policy",
    enable_llm_validation=True,  # Toggle validation
    # ... other settings
)
```

### Criticism Levels

- **HIGH** (default): Require explicit proof of both reachability AND attacker control
- **MEDIUM**: Accept strong evidence for one dimension
- **LOW**: Trust initial classification unless clearly wrong

```python
protocol_policy.validation_criticism_level = "high"
```

### Timeout Configuration

```python
protocol_policy.validation_timeout_seconds = 120  # Per-finding timeout
```

### Error Handling

```python
protocol_policy.validation_fallback_on_error = "invalid"  # Conservative (default)
# Options: "invalid" (filter on error), "valid" (approve on error), "skip" (bypass validation)
```

## Cost Optimization

**Estimated Costs:**
- ProductionRelevanceFilter: ~$0.01 per finding
- LLM Validator: ~$0.10-0.50 per finding
- For 100 findings: $10-50 per scan

**Optimization Strategies:**
1. Use pre-validation gates (automatic, built-in)
2. Adjust criticism level ("medium" or "low" for faster validation)
3. Increase min_checklist_proven_count to filter more before LLM
4. Disable for low-priority scans

## Viewing Results

### Filtered View (Default)

Shows only validated findings. Toggle in UI: "Show only validated findings"

### Unfiltered View

Shows all findings with validation badges:
- ✓ Validated: Passed LLM validation
- ✗ Filtered: Rejected by LLM validation

Click finding to see detailed reasoning in Submission Panel.

## Troubleshooting

### Validation Always Times Out

- Increase `validation_timeout_seconds` (default 120s)
- Check API rate limits
- Reduce `max_turns` in validator (hardcoded to 10)

### Too Many False Negatives

- Lower criticism level to "medium" or "low"
- Check threat model profile is configured correctly
- Review validation reasoning in UI

### Too Many False Positives

- Keep criticism level at "high" (default)
- Increase `min_checklist_proven_count`
- Review pre-validation gates

### High API Costs

- Disable validation for low-priority scans
- Increase `min_checklist_proven_count` to filter more
- Use "medium" criticism level

## API Key Setup

Set environment variable:
```bash
export ANTHROPIC_API_KEY=your-key-here
```

Or in `.env` file:
```
ANTHROPIC_API_KEY=your-key-here
```

Validation automatically disabled if API key not found.
```

**Step 2: Save user guide**

```bash
# Save the guide
cat > docs/LLM_VALIDATION_GUIDE.md << 'EOF'
[paste content above]
EOF
```

**Step 3: Run manual testing checklist**

Manual testing scenarios:

1. **Test validation enabled:**
   - Create scan with protocol policy where `enable_llm_validation=True`
   - Verify findings have `validation_result`
   - Verify report toggle works

2. **Test validation disabled:**
   - Create scan with `enable_llm_validation=False`
   - Verify all findings auto-approved
   - Verify no LLM API calls made

3. **Test different criticism levels:**
   - Run same finding with HIGH, MEDIUM, LOW
   - Verify HIGH is most conservative

4. **Test timeout handling:**
   - Set very short timeout (1 second)
   - Verify findings marked INVALID with timeout category

5. **Test without API key:**
   - Unset ANTHROPIC_API_KEY
   - Verify warning logged
   - Verify validation disabled gracefully

6. **Test UI toggle:**
   - Toggle "Show only validated findings"
   - Verify filtered/unfiltered counts correct
   - Verify validation badges display correctly

**Step 4: Commit**

```bash
git add docs/LLM_VALIDATION_GUIDE.md
git commit -m "docs(triage): add LLM validation user guide

Add comprehensive user guide covering:
- Configuration options (enable/disable, criticism levels, timeouts)
- Cost optimization strategies
- Viewing results (filtered vs unfiltered)
- Troubleshooting common issues
- API key setup

Includes manual testing checklist for validation."
```

---

## Execution Options

**Plan complete and saved to `docs/plans/2026-01-27-llm-validation-triage-implementation.md`.**

Two execution options:

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
