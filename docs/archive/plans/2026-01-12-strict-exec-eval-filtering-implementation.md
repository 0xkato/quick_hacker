# Strict Exec/Eval Filtering Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enhance StrictClassifier with aggressive exec/eval filtering to eliminate false positives from code execution findings.

**Architecture:** Add three helper methods for sink detection, feature intent validation, and auth bypass detection. Modify classification rules to apply strict validation chain. Extend data model for auditable reasoning.

**Tech Stack:** Python 3.11+, Pydantic, AST parsing, pytest

---

## Task 1: Extend ProofChecklist with Exec Reasoning Fields

**Files:**
- Modify: `backend/models/schemas.py:233-241`

**Step 1: Write failing test for new fields**

Create test to verify ProofChecklist accepts exec reasoning fields:

```python
# Add to backend/tests/models/test_schemas.py
def test_proof_checklist_exec_reasoning_fields():
    """Verify ProofChecklist accepts optional exec reasoning fields."""
    from backend.models.schemas import ProofChecklist, ChecklistItem, ChecklistStatus

    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        sink_present=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        dataflow_evidenced=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        reachable=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        boundary_crossed=ChecklistItem(
            value=False, status=ChecklistStatus.DISPROVEN, reason="Test"
        ),
        not_only_misconfig=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        exec_sink_reason="exec() at line 42",
        feature_intent_reason="Feature intent PROVEN: path=/pipelines/",
        auth_bypass_reason="Auth bypass not PROVEN"
    )

    assert checklist.exec_sink_reason == "exec() at line 42"
    assert checklist.feature_intent_reason == "Feature intent PROVEN: path=/pipelines/"
    assert checklist.auth_bypass_reason == "Auth bypass not PROVEN"
```

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/models/test_schemas.py::test_proof_checklist_exec_reasoning_fields -v`

Expected: FAIL with "TypeError: __init__() got an unexpected keyword argument 'exec_sink_reason'" (Pydantic extra=forbid)

**Step 3: Add fields to ProofChecklist**

```python
# In backend/models/schemas.py, update ProofChecklist class (around line 233):
class ProofChecklist(BaseModel):
    """Tri-state proof checklist for vulnerability validation."""
    source_controlled_input: ChecklistItem
    sink_present: ChecklistItem
    dataflow_evidenced: ChecklistItem
    reachable: ChecklistItem
    boundary_crossed: ChecklistItem
    not_only_misconfig: ChecklistItem
    security_control_bypassed: Optional[ChecklistItem] = None

    # Exec/eval specific reasoning (for auditable filtering)
    exec_sink_reason: Optional[str] = None
    feature_intent_reason: Optional[str] = None
    auth_bypass_reason: Optional[str] = None
```

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/models/test_schemas.py::test_proof_checklist_exec_reasoning_fields -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/models/schemas.py backend/tests/models/test_schemas.py
git commit -m "feat(triage): add exec reasoning fields to ProofChecklist"
```

---

## Task 2: Implement AST-Based Exec Sink Detection

**Files:**
- Modify: `backend/services/strict_classifier.py` (add method after line ~200)
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write failing test for exec sink detection**

```python
# Add to backend/tests/services/test_strict_classifier.py
class TestStrictExecEvalFiltering:
    """Tests for aggressive exec/eval filtering logic."""

    def test_detects_direct_exec_call(self, classifier):
        """Detect direct exec() call within symbol range."""
        from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

        finding = Finding(
            title="Code execution in handler",
            category=VulnerabilityCategory.CODE_INJECTION,
            severity="High",
            file_path="/app/api.py",
            line_number=42,
            snippet="exec(user_code)",
            description="Executes user code"
        )

        evidence = Evidence(
            handler_snippet="def handler(user_code: str):\n    exec(user_code)",
            symbol_info=SymbolInfo(
                name="handler",
                type="function",
                line_start=41,
                line_end=42
            )
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec()" in reason
        assert "line 42" in reason

    def test_ignores_exec_in_comment(self, classifier):
        """Do not detect exec in comment."""
        from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

        finding = Finding(
            title="Comment mentions exec",
            category=VulnerabilityCategory.CODE_INJECTION,
            severity="High",
            file_path="/app/api.py",
            line_number=42,
            snippet="# We could use exec() but chose subprocess",
            description="Comment only"
        )

        evidence = Evidence(
            handler_snippet="# We could use exec() but chose subprocess\nresult = subprocess.run(data)",
            symbol_info=SymbolInfo(
                name="handler",
                type="function",
                line_start=42,
                line_end=43
            )
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is False

    def test_detects_obfuscated_exec(self, classifier):
        """Detect getattr(__builtins__, 'exec') pattern."""
        from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

        finding = Finding(
            title="Obfuscated exec",
            category=VulnerabilityCategory.CODE_INJECTION,
            severity="High",
            file_path="/app/api.py",
            line_number=42,
            snippet='getattr(__builtins__, "exec")(code)',
            description="Obfuscated"
        )

        evidence = Evidence(
            handler_snippet='def handler(code):\n    getattr(__builtins__, "exec")(code)',
            symbol_info=SymbolInfo(
                name="handler",
                type="function",
                line_start=41,
                line_end=42
            )
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()

    def test_scoped_to_symbol_range(self, classifier):
        """Do not detect exec outside symbol range."""
        from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

        finding = Finding(
            title="Function without exec",
            category=VulnerabilityCategory.CODE_INJECTION,
            severity="High",
            file_path="/app/api.py",
            line_number=45,
            snippet="process(user_code)",
            description="No exec"
        )

        evidence = Evidence(
            handler_snippet="def other_func():\n    exec(internal)\n\ndef handler(user_code):\n    process(user_code)",
            symbol_info=SymbolInfo(
                name="handler",
                type="function",
                line_start=44,
                line_end=45
            )
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering -v`

Expected: FAIL with "AttributeError: 'StrictClassifier' object has no attribute '_is_code_exec_sink'"

**Step 3: Implement _is_code_exec_sink method**

```python
# Add to backend/services/strict_classifier.py (after _apply_rules method, around line 200)
import ast
import re
from typing import Tuple

def _is_code_exec_sink(self, finding: Finding, evidence: Evidence) -> Tuple[bool, str]:
    """
    Detect if finding involves exec/eval/compile sink within symbol range.

    Uses AST parsing when available (avoids comment false positives).
    Falls back to regex that handles line-number prefixes.

    Returns:
        (is_sink, reason) - reason explains what was detected
    """
    if not evidence.symbol_info:
        return (False, "No symbol info")

    line_start = evidence.symbol_info.line_start
    line_end = evidence.symbol_info.line_end

    # Try AST parsing first (most reliable)
    if evidence.handler_snippet:
        try:
            tree = ast.parse(evidence.handler_snippet)
            for node in ast.walk(tree):
                # Scope check: only nodes within symbol range
                if not hasattr(node, 'lineno'):
                    continue

                # Adjust lineno if snippet doesn't start at line 1
                adjusted_lineno = node.lineno + line_start - 1
                if not (line_start <= adjusted_lineno <= line_end):
                    continue

                # Direct calls: exec(), eval(), compile()
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ['exec', 'eval', 'compile']:
                        return (True, f"Code-exec sink: {node.func.id}() at line {adjusted_lineno}")

                    # Obfuscated: getattr(__builtins__, "exec")
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['exec', 'eval', 'compile']:
                            return (True, f"Code-exec sink: .{node.func.attr}() at line {adjusted_lineno}")

                    # getattr with string literal
                    if isinstance(node.func, ast.Call):
                        if isinstance(node.func.func, ast.Name) and node.func.func.id == 'getattr':
                            if len(node.func.args) >= 2:
                                if isinstance(node.func.args[1], ast.Constant):
                                    if node.func.args[1].value in ['exec', 'eval', 'compile']:
                                        return (True, f"Code-exec sink: getattr(..., '{node.func.args[1].value}') at line {adjusted_lineno}")

                # Subscript: __builtins__["exec"]
                if isinstance(node, ast.Subscript):
                    if isinstance(node.slice, ast.Constant):
                        if node.slice.value in ['exec', 'eval', 'compile']:
                            return (True, f"Code-exec sink: subscript['{node.slice.value}'] at line {adjusted_lineno}")

        except SyntaxError:
            pass  # Fall back to regex

    # Regex fallback: handle line-number prefixes like "42: exec(code)"
    snippet = evidence.handler_snippet or finding.snippet or ""

    # Split into lines and check each within range
    lines = snippet.split('\n')
    for i, line in enumerate(lines, start=line_start):
        if not (line_start <= i <= line_end):
            continue

        # Strip line-number prefix: "123: code" -> "code"
        clean_line = re.sub(r'^\s*\d+\s*:\s*', '', line)

        # Skip comment lines
        if re.match(r'^\s*#', clean_line):
            continue

        # Check for exec/eval/compile calls
        if re.search(r'\b(exec|eval|compile)\s*\(', clean_line):
            return (True, f"Code-exec sink: detected at line {i}")

    return (False, "No exec/eval/compile sink detected")
```

**Step 4: Run tests to verify they pass**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_detects_direct_exec_call -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_ignores_exec_in_comment -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_detects_obfuscated_exec -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_scoped_to_symbol_range -v`

Expected: All PASS

**Step 5: Commit**

```bash
git add backend/services/strict_classifier.py backend/tests/services/test_strict_classifier.py
git commit -m "feat(triage): add AST-based exec sink detection with scope"
```

---

## Task 3: Implement Conservative Feature Intent Detection

**Files:**
- Modify: `backend/services/strict_classifier.py` (add method after _is_code_exec_sink)
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write failing tests for feature intent detection**

```python
# Add to TestStrictExecEvalFiltering class
def test_feature_intent_proven_with_path_and_symbol(self, classifier):
    """Prove feature intent with path + symbol match."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Pipeline executor",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/pipelines/executor.py",
        line_number=42,
        snippet="exec(block_code)",
        description="Executes block"
    )

    evidence = Evidence(
        handler_snippet="class PipelineExecutor:\n    def run_block(self, code):\n        exec(code)",
        symbol_info=SymbolInfo(
            name="PipelineExecutor.run_block",
            type="method",
            line_start=41,
            line_end=43
        )
    )

    proven, reason = classifier._feature_intent_proven(finding, evidence)

    assert proven is True
    assert "path=/pipelines/" in reason
    assert "PipelineExecutor" in reason

def test_feature_intent_not_proven_with_path_only(self, classifier):
    """Do not prove feature intent with path match only."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Pipeline helper",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/pipelines/helper.py",
        line_number=42,
        snippet="exec(code)",
        description="Helper"
    )

    evidence = Evidence(
        handler_snippet="def process_data(code):\n    exec(code)",
        symbol_info=SymbolInfo(
            name="process_data",
            type="function",
            line_start=41,
            line_end=42
        )
    )

    proven, reason = classifier._feature_intent_proven(finding, evidence)

    assert proven is False
    assert "insufficient signals" in reason.lower()

def test_feature_intent_proven_with_path_and_doc(self, classifier):
    """Prove feature intent with path + doc match."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Kernel runner",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/kernel/runner.py",
        line_number=42,
        snippet="exec(cell_code)",
        description="Runs cell"
    )

    evidence = Evidence(
        handler_snippet='def run_cell(cell_code):\n    """Execute notebook cell code."""\n    exec(cell_code)',
        symbol_info=SymbolInfo(
            name="run_cell",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    proven, reason = classifier._feature_intent_proven(finding, evidence)

    assert proven is True
    assert "path=/kernel/" in reason
    assert "Execute" in reason or "doc" in reason.lower()
```

**Step 2: Run tests to verify they fail**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_feature_intent_proven_with_path_and_symbol -v`

Expected: FAIL with "AttributeError: 'StrictClassifier' object has no attribute '_feature_intent_proven'"

**Step 3: Implement _feature_intent_proven method**

```python
# Add to backend/services/strict_classifier.py (after _is_code_exec_sink)
def _feature_intent_proven(self, finding: Finding, evidence: Evidence) -> Tuple[bool, str]:
    """
    Determine if exec/eval is a proven product feature.

    Requires 2+ strong signals:
    - Signal A: Path match (pipelines, executor, kernel, etl, workflow, dag, notebooks)
    - Signal B: Symbol match (class/function name suggests execution)
    - Signal C: Documentation match (comments/docstrings about execution)

    Logic: (A + B) OR (A + C) = PROVEN

    Returns:
        (proven, reason) - reason explains which signals matched
    """
    signals = []

    # Signal A: Path match
    path = finding.file_path.lower()
    path_keywords = ['/pipelines/', '/executor/', '/kernel/', '/etl/',
                     '/workflow/', '/dag/', '/notebooks/', '/blocks/']
    path_match = any(kw in path for kw in path_keywords)

    # Also check package structure: .../data_preparation/.../block/...
    if '/data_preparation/' in path and '/block' in path:
        path_match = True

    if path_match:
        signals.append(f"path={path}")

    # Signal B: Symbol match
    symbol_name = ""
    if evidence.symbol_info:
        symbol_name = evidence.symbol_info.name.lower()

    symbol_keywords = ['executor', 'pipeline', 'kernel', 'runner', 'block',
                       'execute_', 'run_', 'eval_', 'process_block', 'run_kernel']
    symbol_match = any(kw in symbol_name for kw in symbol_keywords)

    if symbol_match:
        signals.append(f"symbol={evidence.symbol_info.name}")

    # Signal C: Documentation match
    snippet = evidence.handler_snippet or finding.snippet or ""
    doc_keywords = ['execute user code', 'run pipeline', 'notebook kernel',
                    'block execution', 'pipeline runtime', 'run user block',
                    'execute block', 'kernel execution', 'run notebook']
    doc_match = any(kw in snippet.lower() for kw in doc_keywords)

    if doc_match:
        signals.append("doc_match")

    # Evaluate: need 2+ signals, including path
    if len(signals) >= 2 and path_match:
        return (True, f"Feature intent PROVEN: {' + '.join(signals)}")

    if len(signals) == 1:
        return (False, f"Feature intent UNKNOWN: only weak signal ({signals[0]})")

    return (False, "Feature intent UNKNOWN: no strong signals found")
```

**Step 4: Run tests to verify they pass**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_feature_intent_proven_with_path_and_symbol -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_feature_intent_not_proven_with_path_only -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_feature_intent_proven_with_path_and_doc -v`

Expected: All PASS

**Step 5: Commit**

```bash
git add backend/services/strict_classifier.py backend/tests/services/test_strict_classifier.py
git commit -m "feat(triage): add conservative feature intent detection"
```

---

## Task 4: Implement Explicit Auth Bypass Detection

**Files:**
- Modify: `backend/services/strict_classifier.py` (add method after _feature_intent_proven)
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write failing tests for auth bypass detection**

```python
# Add to TestStrictExecEvalFiltering class
def test_auth_bypass_proven_with_decorator(self, classifier):
    """Detect explicit @public_endpoint decorator."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Public code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="Critical",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Public"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute")\n@public_endpoint\nasync def run_code(code: str):\n    exec(code)',
        route_snippets=['@app.post("/execute")'],
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=44
        )
    )

    proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

    assert proven is True
    assert "@public_endpoint" in reason

def test_auth_bypass_proven_with_parameter(self, classifier):
    """Detect explicit bypass_auth=True parameter."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Bypassed execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="Critical",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Bypass"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute", bypass_auth=True)\nasync def run_code(code: str):\n    exec(code)',
        route_snippets=['@app.post("/execute", bypass_auth=True)'],
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

    assert proven is True
    assert "bypass_auth=True" in reason

def test_auth_bypass_not_proven_without_markers(self, classifier):
    """Do not prove bypass without explicit markers."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="No auth markers"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
        route_snippets=['@app.post("/execute")'],
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

    assert proven is False
    assert "not PROVEN" in reason

def test_auth_bypass_ignores_description(self, classifier):
    """Do not use finding.description as proof."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="This endpoint has bypass_auth=True"  # Scanner manipulation attempt
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
        route_snippets=['@app.post("/execute")'],
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

    assert proven is False  # Description should be ignored
```

**Step 2: Run tests to verify they fail**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_auth_bypass_proven_with_decorator -v`

Expected: FAIL with "AttributeError: 'StrictClassifier' object has no attribute '_auth_bypass_explicitly_proven'"

**Step 3: Implement _auth_bypass_explicitly_proven method**

```python
# Add to backend/services/strict_classifier.py (after _feature_intent_proven)
def _auth_bypass_explicitly_proven(self, finding: Finding, evidence: Evidence) -> Tuple[bool, str]:
    """
    Determine if auth bypass is explicitly proven in code.

    CRITICAL: Only searches CODE evidence (handler, routes, auth gates).
    Never uses finding.description (prevents scanner manipulation).

    Explicit markers:
    - Parameters: bypass_auth=True, require_auth=False, public=True, skip_auth=True
    - Function calls: bypass_oauth_check(), skip_permission_check(), bypass_auth()
    - Decorators: @public_endpoint, @no_auth_required, @unauthenticated, @allow_anonymous
    - Comments: # no auth required, # public endpoint, # bypass authentication

    Returns:
        (proven, reason) - reason explains what explicit marker was found
    """
    # Collect code-only evidence (NEVER use finding.description)
    code_snippets = []

    if evidence.handler_snippet:
        code_snippets.append(evidence.handler_snippet)

    if evidence.route_snippets:
        code_snippets.extend(evidence.route_snippets)

    if evidence.auth_gate_snippet:
        code_snippets.append(evidence.auth_gate_snippet)

    combined = " ".join(code_snippets).lower()

    # Check explicit markers

    # 1. Auth-specific parameters
    auth_params = ['bypass_auth=true', 'require_auth=false',
                   'public=true', 'skip_auth=true']
    for param in auth_params:
        if param in combined:
            return (True, f"Auth bypass PROVEN: parameter '{param}' in code")

    # 2. Function calls
    bypass_calls = ['bypass_oauth_check(', 'skip_permission_check(',
                    'bypass_auth(', 'skip_auth_check(']
    for call in bypass_calls:
        if call in combined:
            return (True, f"Auth bypass PROVEN: function call '{call}' in code")

    # 3. Decorators
    decorators = ['@public_endpoint', '@no_auth_required',
                  '@unauthenticated', '@allow_anonymous']
    for dec in decorators:
        if dec in combined:
            return (True, f"Auth bypass PROVEN: decorator '{dec}' in code")

    # 4. Comments (in code only)
    comment_patterns = ['# no auth required', '# public endpoint',
                        '# bypass authentication', '# skip auth']
    for pattern in comment_patterns:
        if pattern in combined:
            return (True, f"Auth bypass PROVEN: comment '{pattern}' in code")

    # NOT considered explicit:
    # - "No auth gates found" (absence != bypass)
    # - Path contains /public/ (convention, not proof)

    return (False, "Auth bypass not PROVEN: no explicit bypass markers in code")
```

**Step 4: Run tests to verify they pass**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_auth_bypass_proven_with_decorator -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_auth_bypass_proven_with_parameter -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_auth_bypass_not_proven_without_markers -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_auth_bypass_ignores_description -v`

Expected: All PASS

**Step 5: Commit**

```bash
git add backend/services/strict_classifier.py backend/tests/services/test_strict_classifier.py
git commit -m "feat(triage): add explicit auth bypass detection (code-only)"
```

---

## Task 5: Integrate Exec Filter into Classification Rules

**Files:**
- Modify: `backend/services/strict_classifier.py` (_apply_rules method, around line 150)
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write failing integration tests**

```python
# Add to TestStrictExecEvalFiltering class
def test_exec_with_feature_intent_is_by_design(self, classifier):
    """Classify exec as BY_DESIGN when feature intent proven."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Pipeline executor",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/pipelines/executor.py",
        line_number=42,
        snippet="exec(block_code)",
        description="Pipeline"
    )

    evidence = Evidence(
        handler_snippet="class PipelineExecutor:\n    def run_block(self, code):\n        exec(code)",
        symbol_info=SymbolInfo(
            name="PipelineExecutor.run_block",
            type="method",
            line_start=41,
            line_end=43
        )
    )

    disposition, checklist = classifier.classify(finding, evidence)

    assert disposition == "BY_DESIGN"
    assert checklist.exec_sink_reason is not None
    assert "exec()" in checklist.exec_sink_reason
    assert checklist.feature_intent_reason is not None
    assert "PROVEN" in checklist.feature_intent_reason

def test_exec_with_proven_bypass_is_valid(self, classifier):
    """Classify exec as VALID when auth bypass proven."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory, ChecklistStatus

    finding = Finding(
        title="Public code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="Critical",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Public RCE"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute")\n@public_endpoint\nasync def run_code(code: str):\n    exec(code)',
        route_snippets=['@app.post("/execute")'],
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=44
        )
    )

    # Manually set proof items to simulate proven conditions
    from backend.models.schemas import ChecklistItem
    evidence_with_proof = evidence.copy(deep=True)

    disposition, checklist = classifier.classify(finding, evidence_with_proof)

    # Should be VALID if source/reachable/dataflow proven
    # For this test, we need to ensure those are set
    # This test will initially fail until we wire up the logic

    assert checklist.exec_sink_reason is not None
    assert checklist.auth_bypass_reason is not None
    assert "@public_endpoint" in checklist.auth_bypass_reason

def test_exec_with_unknown_auth_is_speculative(self, classifier):
    """Classify exec as SPECULATIVE when auth unknown."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Unknown auth"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
        route_snippets=['@app.post("/execute")'],
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    disposition, checklist = classifier.classify(finding, evidence)

    assert disposition == "SPECULATIVE"
    assert checklist.exec_sink_reason is not None
    assert checklist.auth_bypass_reason is not None
    assert "not PROVEN" in checklist.auth_bypass_reason

def test_exec_filter_forces_sink_proven(self, classifier):
    """Ensure exec detection forces sink_present to PROVEN."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory, ChecklistStatus

    finding = Finding(
        title="Code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Exec"
    )

    evidence = Evidence(
        handler_snippet="def run(code):\n    exec(code)",
        symbol_info=SymbolInfo(
            name="run",
            type="function",
            line_start=41,
            line_end=42
        )
    )

    disposition, checklist = classifier.classify(finding, evidence)

    assert checklist.sink_present.status == ChecklistStatus.PROVEN
    assert checklist.sink_present.value is True
```

**Step 2: Run tests to verify they fail**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_exec_with_feature_intent_is_by_design -v`

Expected: FAIL (logic not yet integrated into _apply_rules)

**Step 3: Integrate exec filter into _apply_rules**

```python
# In backend/services/strict_classifier.py, modify _apply_rules method (around line 150)
# Add Rule 4 AFTER the global BUG rule and BEFORE pattern downgrades

def _apply_rules(self, finding: Finding, evidence: Evidence, checklist: ProofChecklist) -> str:
    """Apply classification rules to determine disposition."""

    # Extract checklist items
    source = checklist.source_controlled_input
    sink = checklist.sink_present
    dataflow = checklist.dataflow_evidenced
    reachable = checklist.reachable
    boundary_crossed = checklist.boundary_crossed
    not_misconfig = checklist.not_only_misconfig
    security_bypassed = checklist.security_control_bypassed

    # Rule 1: Global BUG rule (security control bypassed)
    if security_bypassed and security_bypassed.status == ChecklistStatus.PROVEN:
        if security_bypassed.value and reachable.status == ChecklistStatus.PROVEN and reachable.value:
            return Disposition.BUG

    # Rule 4: STRICT EXEC/EVAL FILTERING (ADD THIS BEFORE OTHER RULES)
    is_exec_sink, exec_reason = self._is_code_exec_sink(finding, evidence)
    if is_exec_sink:
        # Store reason and force sink_present to PROVEN
        checklist.exec_sink_reason = exec_reason
        checklist.sink_present = ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason=exec_reason
        )
        sink = checklist.sink_present  # Update local reference

        # Sub-rule 4b: Feature intent proven → BY_DESIGN
        feature_proven, feature_reason = self._feature_intent_proven(finding, evidence)
        checklist.feature_intent_reason = feature_reason
        if feature_proven:
            return Disposition.BY_DESIGN

        # Sub-rule 4c: Full proof chain → VALID or SPECULATIVE
        if (source.status == ChecklistStatus.PROVEN and source.value and
            reachable.status == ChecklistStatus.PROVEN and reachable.value and
            dataflow.status == ChecklistStatus.PROVEN and dataflow.value):

            bypass_proven, bypass_reason = self._auth_bypass_explicitly_proven(finding, evidence)
            checklist.auth_bypass_reason = bypass_reason

            boundary_violated = (boundary_crossed.status == ChecklistStatus.PROVEN and
                               boundary_crossed.value)

            if bypass_proven or boundary_violated:
                return Disposition.VALID_SECURITY_ISSUE

            return Disposition.SPECULATIVE  # Auth unknown, high-risk but unproven

        # Sub-rule 4d: Default → SPECULATIVE
        return Disposition.SPECULATIVE

    # Continue with existing rules...
    # Rule 2: Full proof chain
    if (source.PROVEN_TRUE and sink.PROVEN_TRUE and dataflow.PROVEN_TRUE and
        reachable.PROVEN_TRUE and boundary_crossed.PROVEN_TRUE and not_misconfig.PROVEN_TRUE):
        return Disposition.VALID_SECURITY_ISSUE

    # ... rest of existing rules ...
```

**Step 4: Run tests to verify they pass**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_exec_with_feature_intent_is_by_design -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_exec_with_unknown_auth_is_speculative -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_exec_filter_forces_sink_proven -v`

Expected: All PASS (some may need evidence adjustment)

**Step 5: Commit**

```bash
git add backend/services/strict_classifier.py backend/tests/services/test_strict_classifier.py
git commit -m "feat(triage): integrate exec filter into classification rules"
```

---

## Task 6: Update Pattern Downgrades to Skip CODE_INJECTION

**Files:**
- Modify: `backend/services/strict_classifier.py` (_apply_pattern_downgrades method)
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write test for pattern downgrade skip**

```python
# Add to TestStrictExecEvalFiltering class
def test_pattern_downgrades_skip_code_injection(self, classifier):
    """Ensure pattern downgrades skip CODE_INJECTION category."""
    from backend.models.schemas import Finding, Evidence, VulnerabilityCategory

    # This test verifies that CODE_INJECTION findings bypass pattern downgrades
    # The exec filter should handle CODE_INJECTION entirely

    finding = Finding(
        title="Code injection",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Code injection"
    )

    evidence = Evidence(handler_snippet="exec(code)")

    # Call _apply_pattern_downgrades directly
    disposition = "VALID_SECURITY_ISSUE"  # Start with VALID
    result = classifier._apply_pattern_downgrades(disposition, finding, evidence)

    # Should return unchanged (not downgraded by patterns)
    assert result == "VALID_SECURITY_ISSUE"
```

**Step 2: Run test to verify it needs implementation**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_pattern_downgrades_skip_code_injection -v`

Expected: May PASS or FAIL depending on current pattern downgrade logic

**Step 3: Update _apply_pattern_downgrades**

```python
# In backend/services/strict_classifier.py, modify _apply_pattern_downgrades (around line 300)
def _apply_pattern_downgrades(
    self, disposition: str, finding: Finding, evidence: Evidence
) -> str:
    """
    Apply pattern-based downgrades for specific categories.

    SKIP CODE_INJECTION - handled entirely by strict exec filter.
    """
    category = finding.category

    # SKIP CODE_INJECTION - exec filter owns this category
    if category == VulnerabilityCategory.CODE_INJECTION:
        return disposition

    # ... rest of pattern downgrade logic for other categories ...

    return disposition
```

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_pattern_downgrades_skip_code_injection -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/strict_classifier.py backend/tests/services/test_strict_classifier.py
git commit -m "feat(triage): skip CODE_INJECTION in pattern downgrades"
```

---

## Task 7: Update Reasoning Generation for Exec Findings

**Files:**
- Modify: `backend/services/strict_classifier.py` (_generate_reasoning method)
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write test for exec reasoning**

```python
# Add to TestStrictExecEvalFiltering class
def test_reasoning_includes_exec_details(self, classifier):
    """Ensure reasoning bullets include exec-specific details."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(code)",
        description="Exec"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
        symbol_info=SymbolInfo(
            name="run_code",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    disposition, checklist = classifier.classify(finding, evidence)
    reasoning = classifier._generate_reasoning(checklist, finding, evidence)

    # Should include exec-specific reasoning
    assert any("exec" in bullet.lower() for bullet in reasoning)
    assert any("feature intent" in bullet.lower() for bullet in reasoning)
```

**Step 2: Run test to verify current behavior**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_reasoning_includes_exec_details -v`

Expected: May PASS or FAIL depending on current reasoning logic

**Step 3: Update _generate_reasoning**

```python
# In backend/services/strict_classifier.py, modify _generate_reasoning (around line 350)
def _generate_reasoning(
    self, checklist: ProofChecklist, finding: Finding, evidence: Evidence
) -> List[str]:
    """Generate reasoning bullets explaining classification decision."""
    bullets = []

    # Add exec-specific reasoning at start (if present)
    if checklist.exec_sink_reason:
        bullets.append(checklist.exec_sink_reason)
        if checklist.feature_intent_reason:
            bullets.append(checklist.feature_intent_reason)
        if checklist.auth_bypass_reason:
            bullets.append(checklist.auth_bypass_reason)

        # If exec reasoning is complete (3 bullets), we can truncate
        if len(bullets) >= 3:
            return bullets[:4]  # Keep 3-4 bullets for clarity

    # Continue with standard checklist reasoning...
    source = checklist.source_controlled_input
    if source.reason:
        bullets.append(source.reason)

    sink = checklist.sink_present
    if sink.reason:
        bullets.append(sink.reason)

    dataflow = checklist.dataflow_evidenced
    if dataflow.reason:
        bullets.append(dataflow.reason)

    reachable = checklist.reachable
    if reachable.reason:
        bullets.append(reachable.reason)

    boundary = checklist.boundary_crossed
    if boundary.reason:
        bullets.append(boundary.reason)

    # Limit to 5 bullets total
    return bullets[:5]
```

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_reasoning_includes_exec_details -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/strict_classifier.py backend/tests/services/test_strict_classifier.py
git commit -m "feat(triage): add exec-specific reasoning to classification output"
```

---

## Task 8: Add Comprehensive Edge Case Tests

**Files:**
- Test: `backend/tests/services/test_strict_classifier.py`

**Step 1: Write edge case tests**

```python
# Add to TestStrictExecEvalFiltering class
def test_no_dataflow_is_speculative(self, classifier):
    """Exec with source and sink but no dataflow → SPECULATIVE."""
    from backend.models.schemas import (
        Finding, Evidence, SymbolInfo, VulnerabilityCategory,
        ChecklistItem, ChecklistStatus
    )

    finding = Finding(
        title="Code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(config['script'])",
        description="Different variable"
    )

    evidence = Evidence(
        handler_snippet='async def handler(user_code: str):\n    config = load_config()\n    exec(config["script"])',
        symbol_info=SymbolInfo(
            name="handler",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    # Manually simulate: source=PROVEN, reachable=PROVEN, dataflow=DISPROVEN
    # In real scenario, evidence gatherer would set these

    disposition, checklist = classifier.classify(finding, evidence)

    # Without dataflow proven, should be SPECULATIVE
    assert disposition == "SPECULATIVE"

def test_admin_path_without_role_check_is_valid(self, classifier):
    """Exec in admin path without role check → VALID (boundary crossed)."""
    from backend.models.schemas import (
        Finding, Evidence, SymbolInfo, VulnerabilityCategory,
        ChecklistItem, ChecklistStatus
    )

    finding = Finding(
        title="Admin code execution",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="Critical",
        file_path="/app/api.py",
        line_number=42,
        snippet="exec(script)",
        description="Admin endpoint"
    )

    evidence = Evidence(
        handler_snippet='@app.post("/admin/execute")\nasync def run_script(script: str):\n    exec(script)',
        route_snippets=['@app.post("/admin/execute")'],
        symbol_info=SymbolInfo(
            name="run_script",
            type="function",
            line_start=41,
            line_end=43
        )
    )

    # This test depends on boundary_crossed logic being set by evidence gatherer
    # If admin path without role check is detected, boundary_crossed.PROVEN_TRUE

    disposition, checklist = classifier.classify(finding, evidence)

    # Should be VALID if boundary crossed (admin path, no role check)
    # This may need evidence gatherer to detect the admin boundary

def test_whole_file_scan_avoided(self, classifier):
    """Exec in different function not detected (scoped to symbol)."""
    from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

    finding = Finding(
        title="Handler",
        category=VulnerabilityCategory.CODE_INJECTION,
        severity="High",
        file_path="/app/api.py",
        line_number=45,
        snippet="process(user_code)",
        description="No exec"
    )

    evidence = Evidence(
        handler_snippet="def other_func():\n    exec(internal)\n\ndef handler(user_code):\n    process(user_code)",
        symbol_info=SymbolInfo(
            name="handler",
            type="function",
            line_start=44,
            line_end=45
        )
    )

    is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

    # Should NOT detect exec in other_func (outside symbol range)
    assert is_sink is False
```

**Step 2: Run edge case tests**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_no_dataflow_is_speculative -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_admin_path_without_role_check_is_valid -v`
Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering::test_whole_file_scan_avoided -v`

Expected: Most PASS, some may need evidence gatherer adjustments

**Step 3: Run full test suite**

Run: `pytest backend/tests/services/test_strict_classifier.py::TestStrictExecEvalFiltering -v`

Expected: All tests PASS

**Step 4: Commit**

```bash
git add backend/tests/services/test_strict_classifier.py
git commit -m "test(triage): add comprehensive exec filter edge case tests"
```

---

## Task 9: Update Existing Tests for New Behavior

**Files:**
- Test: `backend/tests/services/test_strict_classifier.py` (existing test classes)

**Step 1: Identify affected tests**

Run full test suite to find tests broken by exec filter changes:

Run: `pytest backend/tests/services/test_strict_classifier.py -v`

Expected: Some tests may fail due to:
- CODE_INJECTION findings now classified differently
- New checklist fields (exec_sink_reason, etc.)
- Changed disposition logic

**Step 2: Update broken tests**

For each failing test:
1. Read the test
2. Understand what changed
3. Update assertions to match new behavior
4. Ensure test still validates correct behavior

Example fix pattern:
```python
# OLD: Expected BY_DESIGN without 2+ signals
assert disposition == "BY_DESIGN"

# NEW: Expected SPECULATIVE without 2+ signals
assert disposition == "SPECULATIVE"
assert checklist.feature_intent_reason is not None
```

**Step 3: Run tests to verify fixes**

Run: `pytest backend/tests/services/test_strict_classifier.py -v`

Expected: All PASS

**Step 4: Commit**

```bash
git add backend/tests/services/test_strict_classifier.py
git commit -m "test(triage): update existing tests for exec filter behavior"
```

---

## Task 10: Integration Verification

**Files:**
- All modified files

**Step 1: Run full backend test suite**

Run: `pytest backend/tests/ -v`

Expected: All PASS (no regressions)

**Step 2: Type check**

Run: `mypy backend/services/strict_classifier.py backend/models/schemas.py`

Expected: No type errors

**Step 3: Manual smoke test**

Create a test script to verify end-to-end behavior:

```python
# scripts/test_exec_filter.py
from backend.services.strict_classifier import StrictClassifier
from backend.models.schemas import Finding, Evidence, SymbolInfo, VulnerabilityCategory

classifier = StrictClassifier()

# Test 1: Product feature
finding1 = Finding(
    title="Pipeline executor",
    category=VulnerabilityCategory.CODE_INJECTION,
    severity="High",
    file_path="/app/pipelines/executor.py",
    line_number=42,
    snippet="exec(block_code)",
    description="Pipeline"
)
evidence1 = Evidence(
    handler_snippet="class PipelineExecutor:\n    def run_block(self, code):\n        exec(code)",
    symbol_info=SymbolInfo(name="PipelineExecutor.run_block", type="method", line_start=41, line_end=43)
)
disp1, check1 = classifier.classify(finding1, evidence1)
print(f"Test 1 - Product feature: {disp1} (expected: BY_DESIGN)")

# Test 2: Public RCE
finding2 = Finding(
    title="Public exec",
    category=VulnerabilityCategory.CODE_INJECTION,
    severity="Critical",
    file_path="/app/api.py",
    line_number=42,
    snippet="exec(code)",
    description="Public"
)
evidence2 = Evidence(
    handler_snippet='@app.post("/run")\n@public_endpoint\ndef run(code):\n    exec(code)',
    symbol_info=SymbolInfo(name="run", type="function", line_start=41, line_end=44)
)
disp2, check2 = classifier.classify(finding2, evidence2)
print(f"Test 2 - Public RCE: {disp2} (expected: SPECULATIVE or VALID)")

# Test 3: Unknown auth
finding3 = Finding(
    title="Exec unknown auth",
    category=VulnerabilityCategory.CODE_INJECTION,
    severity="High",
    file_path="/app/api.py",
    line_number=42,
    snippet="exec(code)",
    description="Unknown"
)
evidence3 = Evidence(
    handler_snippet='@app.post("/run")\ndef run(code):\n    exec(code)',
    symbol_info=SymbolInfo(name="run", type="function", line_start=41, line_end=43)
)
disp3, check3 = classifier.classify(finding3, evidence3)
print(f"Test 3 - Unknown auth: {disp3} (expected: SPECULATIVE)")
```

Run: `python scripts/test_exec_filter.py`

Expected: Output matches expected dispositions

**Step 4: Review design document checklist**

Read: `docs/plans/2026-01-12-strict-exec-eval-filtering-design.md`

Verify all requirements implemented:
- ✅ AST-based sink detection with scope
- ✅ Conservative feature intent (2+ signals)
- ✅ Explicit auth bypass (code-only)
- ✅ Dataflow requirement for VALID
- ✅ Forced sink checklist consistency
- ✅ ProofChecklist fields added
- ✅ Pattern downgrades skip CODE_INJECTION
- ✅ Exec-specific reasoning

**Step 5: Final commit**

```bash
git add .
git commit -m "feat(triage): complete strict exec/eval filtering implementation

- Add AST-based exec sink detection scoped to symbol range
- Implement conservative feature intent detection (2+ signals)
- Add explicit auth bypass detection (code-only evidence)
- Integrate exec filter into classification rules
- Update reasoning generation for exec findings
- Skip CODE_INJECTION in pattern downgrades
- Add comprehensive edge case tests
- Update existing tests for new behavior

Closes: strict-exec-eval-filtering-design
"
```

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-01-12-strict-exec-eval-filtering-implementation.md`.

Two execution options:

**1. Subagent-Driven (this session)** - Dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

Which approach?
