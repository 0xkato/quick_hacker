"""Code Injection classification gate for exec/eval/compile."""
import ast
import re
from typing import Tuple

from models.schemas import Finding, Evidence, Disposition
from .base import BaseGate, GateResult


class CodeInjectionGate(BaseGate):
    """Code injection classification gate for exec/eval/compile sinks."""

    def get_category_name(self) -> str:
        return "CODE_INJECTION"

    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """Evaluate code injection finding with strict exec filter."""
        # Check if this is an exec/eval/compile sink
        is_exec_sink, exec_reason = self._is_code_exec_sink(finding, evidence)

        if not is_exec_sink:
            return GateResult(
                passed=False,
                reasoning=["No exec/eval/compile sink detected"],
                proof_items={
                    "exec_sink_reason": None,
                    "feature_intent_reason": None,
                    "auth_bypass_reason": None
                }
            )

        # Check if this is a proven product feature
        feature_proven, feature_reason = self._feature_intent_proven(finding, evidence)

        # Check auth bypass for security boundaries
        bypass_proven, bypass_reason = self._auth_bypass_explicitly_proven(finding, evidence)

        if feature_proven:
            return GateResult(
                passed=False,
                reasoning=[exec_reason, feature_reason],
                proof_items={
                    "exec_sink_reason": exec_reason,
                    "feature_intent_reason": feature_reason,
                    "auth_bypass_reason": bypass_reason
                },
                disposition=Disposition.BY_DESIGN
            )

        reasoning = [exec_reason]
        if feature_reason:
            reasoning.append(feature_reason)
        if bypass_reason:
            reasoning.append(bypass_reason)

        return GateResult(
            passed=True,
            reasoning=reasoning,
            proof_items={
                "exec_sink_reason": exec_reason,
                "feature_intent_reason": feature_reason,
                "auth_bypass_reason": bypass_reason
            }
        )

    def _is_code_exec_sink(self, finding: Finding, evidence: Evidence) -> Tuple[bool, str]:
        """
        Detect if finding involves exec/eval/compile sink within symbol range.

        Uses AST parsing when available (avoids comment false positives).
        Falls back to regex that handles line-number prefixes.

        Returns:
            (is_sink, reason) - reason explains what was detected
        """
        symbol_name = None
        symbol_type = None

        if evidence.symbol_info:
            symbol_name = evidence.symbol_info["name"]
            symbol_type = evidence.symbol_info["type"]

        # Try AST parsing first (most reliable) - only if we have symbol info
        ast_parse_succeeded = False
        target_node = None
        if evidence.snippet and symbol_name and symbol_type:
            try:
                tree = ast.parse(evidence.snippet)
                ast_parse_succeeded = True

                # Find the target symbol (function or class) in the AST
                for node in ast.walk(tree):
                    if symbol_type == "function" and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name == symbol_name:
                            target_node = node
                            break
                    elif symbol_type == "class" and isinstance(node, ast.ClassDef):
                        if node.name == symbol_name:
                            target_node = node
                            break

                # If we found the target, check only within its body
                if target_node:
                    for node in ast.walk(target_node):
                        # Direct calls: exec(), eval(), compile()
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id in ['exec', 'eval', 'compile']:
                                return (True, f"Code-exec sink: {node.func.id}() in {symbol_name}")

                            # Obfuscated: getattr(__builtins__, "exec")
                            if isinstance(node.func, ast.Attribute):
                                if node.func.attr in ['exec', 'eval', 'compile']:
                                    return (True, f"Code-exec sink: .{node.func.attr}() in {symbol_name}")

                            # getattr with string literal
                            if isinstance(node.func, ast.Call):
                                if isinstance(node.func.func, ast.Name) and node.func.func.id == 'getattr':
                                    if len(node.func.args) >= 2:
                                        if isinstance(node.func.args[1], ast.Constant):
                                            if node.func.args[1].value in ['exec', 'eval', 'compile']:
                                                return (True, f"Code-exec sink: getattr(..., '{node.func.args[1].value}') in {symbol_name}")

                        # Subscript: __builtins__["exec"]
                        if isinstance(node, ast.Subscript):
                            if isinstance(node.slice, ast.Constant):
                                if node.slice.value in ['exec', 'eval', 'compile']:
                                    return (True, f"Code-exec sink: subscript['{node.slice.value}'] in {symbol_name}")

                    # Found the target node and checked it - return False (no sink found)
                    return (False, f"No exec/eval/compile sink in {symbol_name}")

            except SyntaxError:
                pass  # Fall back to regex

        # Use regex fallback if AST parsing failed or couldn't find the symbol
        if not ast_parse_succeeded or target_node is None:
            snippet = evidence.snippet or finding.code_snippet or ""

            for line in snippet.split('\n'):
                # Strip line-number prefix: "123: code" -> "code"
                clean_line = re.sub(r'^\s*\d+\s*:\s*', '', line)

                # Skip comment lines
                if re.match(r'^\s*#', clean_line):
                    continue

                # Check for exec/eval/compile calls (exact word, not part of larger identifier)
                if re.search(r'(?<![a-zA-Z_])(exec|eval|compile)\s*\(', clean_line):
                    return (True, f"Code-exec sink: detected in snippet")

        return (False, "No exec/eval/compile sink detected")

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
            signals.append(f"path={finding.file_path}")

        # Signal B: Symbol match
        symbol_name = ""
        if evidence.symbol_info:
            symbol_name = evidence.symbol_info["name"].lower()

        symbol_keywords = ['executor', 'pipeline', 'kernel', 'runner', 'block',
                           'execute_', 'run_', 'eval_', 'process_block', 'run_kernel']
        symbol_match = any(kw in symbol_name for kw in symbol_keywords)

        if symbol_match:
            signals.append(f"symbol={evidence.symbol_info['name']}")

        # Signal C: Documentation match
        snippet = evidence.snippet or finding.code_snippet or ""
        doc_keywords = ['execute user code', 'run pipeline', 'notebook kernel',
                        'block execution', 'pipeline runtime', 'run user block',
                        'execute block', 'kernel execution', 'run notebook',
                        'notebook cell', 'execute notebook', 'run block', 'execute cell',
                        'pipeline execution', 'dynamic execution', 'code execution']
        doc_match = any(kw in snippet.lower() for kw in doc_keywords)

        if doc_match:
            signals.append("doc_match")

        # Evaluate: need 2+ signals, including path
        if len(signals) >= 2 and path_match:
            return (True, f"Feature intent PROVEN: {' + '.join(signals)}")

        if len(signals) == 1:
            return (False, f"Feature intent UNKNOWN: only weak signal ({signals[0]})")

        return (False, "Feature intent UNKNOWN: no strong signals found")

    def _auth_bypass_explicitly_proven(self, finding: Finding, evidence: Evidence) -> Tuple[bool, str]:
        """
        Determine if auth bypass is explicitly proven in code.

        CRITICAL: Only searches CODE evidence (handler, routes, auth gates).
        Never uses finding.description (prevents scanner manipulation).

        Returns:
            (proven, reason) - reason explains what explicit marker was found
        """
        # Collect code-only evidence (NEVER use finding.description)
        code_snippets = []

        # 1. Handler snippet
        if evidence.snippet:
            code_snippets.append(evidence.snippet)

        # 2. Route snippets (from matches)
        route_matches = [m for m in evidence.matches if m["match_type"] == "route_registration"]
        for match in route_matches:
            code_snippets.append(match["snippet"])

        # 3. Auth gate snippets
        auth_matches = [m for m in evidence.matches if m["match_type"] == "auth_gate"]
        for match in auth_matches:
            code_snippets.append(match["snippet"])

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

        return (False, "Auth bypass not PROVEN: no explicit bypass markers in code")
