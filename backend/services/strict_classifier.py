"""
Strict classifier for vulnerability triage.

Implements tri-state proof checklist and strict disposition rules.
Runs synchronously (called via asyncio.to_thread).
"""

import ast
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from models.schemas import (
    Finding,
    Disposition,
    ChecklistStatus,
    ChecklistItem,
    ProofChecklist,
    VulnerabilityCategory
)
from services.evidence_gatherer import EvidenceResult


@dataclass
class ClassificationResult:
    """Result from classification."""
    disposition: Disposition
    classification_confidence: int  # 0-100
    exploit_confidence: Optional[int]  # 0-100, only for VALID/BUG
    proof_checklist: ProofChecklist
    reasoning: list[str]  # 2-4 bullets
    category: Optional[VulnerabilityCategory] = None


class StrictClassifier:
    """
    Tri-state proof checklist + strict disposition rules.

    Responsibilities:
    - Evaluate A-F checklist items (PROVEN/DISPROVEN/UNKNOWN)
    - Apply disposition rules in priority order
    - Run pattern-based downgrades
    - Return disposition + confidence + reasoning
    """

    def classify(
        self,
        finding: Finding,
        evidence: EvidenceResult
    ) -> ClassificationResult:
        """
        Classify a finding based on evidence.
        Returns: disposition, confidence, checklist, reasoning
        """
        # Normalize category
        category = self._normalize_category(finding)

        # Build tri-state checklist
        checklist = self._build_checklist(finding, evidence)

        # Apply strict disposition rules
        disposition = self._apply_rules(checklist, finding, evidence)

        # Apply pattern downgrades (ONLY downgrades)
        disposition = self._apply_pattern_downgrades(
            disposition, finding, evidence, checklist, category
        )

        # Compute confidence scores
        classification_confidence = self._compute_classification_confidence(
            disposition, checklist
        )

        exploit_confidence = None
        if disposition in [Disposition.VALID_SECURITY_ISSUE, Disposition.BUG]:
            exploit_confidence = self._compute_exploit_confidence(checklist)

        # Generate reasoning bullets
        reasoning = self._generate_reasoning(disposition, checklist, evidence, category)

        return ClassificationResult(
            disposition=disposition,
            classification_confidence=classification_confidence,
            exploit_confidence=exploit_confidence,
            proof_checklist=checklist,
            reasoning=reasoning,
            category=category
        )

    def _normalize_category(self, finding: Finding) -> Optional[VulnerabilityCategory]:
        """Normalize vulnerability type to category enum."""
        vuln_type = finding.vulnerability_type.lower().replace(" ", "_").replace("-", "_")

        # Priority mapping (command injection before generic injection)
        if "command" in vuln_type and "injection" in vuln_type:
            return VulnerabilityCategory.COMMAND_INJECTION
        if "code" in vuln_type and ("injection" in vuln_type or "exec" in vuln_type):
            return VulnerabilityCategory.CODE_INJECTION
        if "sql" in vuln_type or "sqli" in vuln_type:
            return VulnerabilityCategory.SQL_INJECTION
        if vuln_type == "ssrf" or "server_side_request_forgery" in vuln_type:
            return VulnerabilityCategory.SSRF

        # CSWSH: ONLY when wording indicates origin/hijack
        title_and_desc = (finding.title + " " + finding.description).lower()
        if "websocket" in vuln_type and any(
            marker in title_and_desc
            for marker in ["origin", "hijack", "cswsh", "cross-site websocket"]
        ):
            return VulnerabilityCategory.CSWSH

        if "deserial" in vuln_type or "pickle" in vuln_type or "yaml" in vuln_type:
            return VulnerabilityCategory.DESERIALIZATION
        if "secret" in vuln_type or "credential" in vuln_type or "hardcoded" in vuln_type:
            return VulnerabilityCategory.HARDCODED_SECRET
        if "path" in vuln_type and "travers" in vuln_type:
            return VulnerabilityCategory.PATH_TRAVERSAL
        if vuln_type == "xss" or "cross_site_scripting" in vuln_type:
            return VulnerabilityCategory.XSS
        if vuln_type == "csrf" or "cross_site_request_forgery" in vuln_type:
            return VulnerabilityCategory.CSRF
        if "xxe" in vuln_type or "xml_external_entity" in vuln_type:
            return VulnerabilityCategory.XXE
        if "redirect" in vuln_type:
            return VulnerabilityCategory.OPEN_REDIRECT
        if "auth" in vuln_type and "bypass" in vuln_type:
            return VulnerabilityCategory.AUTHENTICATION_BYPASS
        if "authori" in vuln_type and "bypass" in vuln_type:
            return VulnerabilityCategory.AUTHORIZATION_BYPASS
        if "information" in vuln_type and "disclos" in vuln_type:
            return VulnerabilityCategory.INFORMATION_DISCLOSURE
        if "dos" in vuln_type or "denial_of_service" in vuln_type:
            return VulnerabilityCategory.DOS
        if "race" in vuln_type:
            return VulnerabilityCategory.RACE_CONDITION

        return VulnerabilityCategory.GENERIC

    def _build_checklist(self, finding: Finding, evidence: EvidenceResult) -> ProofChecklist:
        """Build tri-state proof checklist."""
        return ProofChecklist(
            source_controlled_input=self._evaluate_source_controlled_input(finding, evidence),
            sink_present=self._evaluate_sink_present(finding, evidence),
            dataflow_evidenced=self._evaluate_dataflow_evidenced(finding, evidence),
            reachable=self._evaluate_reachable(finding, evidence),
            boundary_crossed=self._evaluate_boundary_crossed(finding, evidence),
            not_only_misconfig=self._evaluate_not_only_misconfig(finding, evidence),
            security_control_bypassed=self._evaluate_security_control_bypassed(finding, evidence)
        )

    def _evaluate_source_controlled_input(
        self, finding: Finding, evidence: EvidenceResult
    ) -> ChecklistItem:
        """Check if attacker can control the input."""
        # Check for source evidence
        source_matches = [m for m in evidence.matches if m.match_type == "source"]

        if source_matches:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason=f"Found {len(source_matches)} user input sources"
            )

        # Check for explicit "no user input" patterns
        snippet_lower = evidence.snippet.lower()
        if any(marker in snippet_lower for marker in ["constant", "hardcoded", "config", "static"]):
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.DISPROVEN,
                reason="Input appears to be constant or config-only"
            )

        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="No clear user input sources found"
        )

    def _evaluate_sink_present(self, finding: Finding, evidence: EvidenceResult) -> ChecklistItem:
        """Check if dangerous sink exists."""
        sink_matches = [m for m in evidence.matches if m.match_type == "sink"]

        if sink_matches:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason=f"Found {len(sink_matches)} dangerous sinks"
            )

        # Check finding's code snippet for sink patterns
        if finding.code_snippet:
            snippet_lower = finding.code_snippet.lower()
            sink_patterns = [
                "subprocess", "exec", "eval", "system", "popen",
                ".execute(", "yaml.load", "pickle.load", "requests.get", "requests.post"
            ]
            if any(p in snippet_lower for p in sink_patterns):
                return ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="Dangerous function found in code snippet"
                )

        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="No clear dangerous sinks found"
        )

    def _evaluate_dataflow_evidenced(
        self, finding: Finding, evidence: EvidenceResult
    ) -> ChecklistItem:
        """Check if data flows from source to sink."""
        source_matches = [m for m in evidence.matches if m.match_type == "source"]
        sink_matches = [m for m in evidence.matches if m.match_type == "sink"]

        if not source_matches or not sink_matches:
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Missing source or sink for dataflow analysis"
            )

        # Check if source and sink are close (within 50 lines)
        if evidence.symbol_info:
            # Both within same symbol = strong dataflow evidence
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason=f"Source and sink in same function ({evidence.symbol_info.name})"
            )

        # Check proximity
        source_lines = [m.line for m in source_matches]
        sink_lines = [m.line for m in sink_matches]

        min_distance = min(abs(s - k) for s in source_lines for k in sink_lines)

        if min_distance < 50:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason=f"Source and sink within {min_distance} lines"
            )

        # Check for trace in finding
        if finding.source_trace and len(finding.source_trace) > 0:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Source-to-sink trace provided"
            )

        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="No clear dataflow path found"
        )

    def _evaluate_reachable(self, finding: Finding, evidence: EvidenceResult) -> ChecklistItem:
        """Check if code is reachable (STRICT: only route/handler registration)."""
        route_matches = [m for m in evidence.matches if m.match_type == "route_registration"]

        if route_matches:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason=f"Found {len(route_matches)} route registrations"
            )

        # Check finding file path for route-like patterns
        if any(marker in finding.file_path.lower() for marker in [
            "/routes/", "/api/", "/handlers/", "/views/", "/endpoints/"
        ]):
            # Weak evidence - still UNKNOWN
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="File path suggests API but no route registration found"
            )

        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="No route/handler registration found"
        )

    def _evaluate_boundary_crossed(
        self, finding: Finding, evidence: EvidenceResult
    ) -> ChecklistItem:
        """Check if trust boundary is crossed (HTTP/WebSocket)."""
        # Check for HTTP/WebSocket context
        if evidence.framework:
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason=f"Framework detected: {evidence.framework}"
            )

        # Check for source matches that indicate HTTP/WS
        source_matches = [m for m in evidence.matches if m.match_type == "source"]
        if any("request" in m.snippet.lower() or "websocket" in m.snippet.lower()
               for m in source_matches):
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="HTTP/WebSocket input detected"
            )

        # Check file path
        if any(marker in finding.file_path.lower() for marker in [
            "/api/", "/routes/", "/handlers/", "/views/", "/endpoints/", "/websocket/"
        ]):
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="File path indicates HTTP/WebSocket handler"
            )

        # Check for internal markers
        if any(marker in finding.file_path.lower() for marker in [
            "/migration/", "/test/", "/script/", "/internal/", "/cron/"
        ]):
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.DISPROVEN,
                reason="Internal/test/migration context"
            )

        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="Trust boundary unclear"
        )

    def _evaluate_not_only_misconfig(
        self, finding: Finding, evidence: EvidenceResult
    ) -> ChecklistItem:
        """Check if exploitable in default/secure config (STRICT logic)."""
        snippet = (finding.description + " " + evidence.snippet).lower()

        # PROVEN False: explicit evidence exploitation requires disabled security
        misconfig_markers = [
            "when auth disabled", "if not require_auth", "when auth is false",
            "when security disabled", "if debug is true", "in debug mode only",
            "when validation disabled", "if not validate"
        ]

        if any(marker in snippet for marker in misconfig_markers):
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.PROVEN,
                reason="Exploitable only when security explicitly disabled"
            )

        # PROVEN True: explicit public route or auth bypass
        public_markers = [
            "public route", "unauthenticated", "no auth required",
            "skip_auth", "bypass_auth", "public endpoint"
        ]

        if any(marker in snippet for marker in public_markers):
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Route explicitly public or bypasses auth"
            )

        # Check for local auth presence (but no explicit bypass)
        auth_matches = [m for m in evidence.matches if m.match_type == "auth_gate"]
        if auth_matches:
            # Auth present but no explicit bypass = UNKNOWN (could be middleware)
            return ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Auth check present but could be middleware"
            )

        # Default: UNKNOWN
        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="Configuration dependency unclear"
        )

    def _evaluate_security_control_bypassed(
        self, finding: Finding, evidence: EvidenceResult
    ) -> Optional[ChecklistItem]:
        """Check if security control is explicitly bypassed (for BUG)."""
        snippet = (finding.description + " " + evidence.snippet).lower()

        # PROVEN True: explicit bypass markers in same scope
        bypass_markers = [
            "skip_auth", "bypass_auth", "skip_permission", "bypass_rbac",
            "ignore_auth", "disable_auth", "skip_check", "bypass_check",
            "auth=false", "auth: false", "skip=true", "skip: true"
        ]

        if any(marker in snippet for marker in bypass_markers):
            return ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Explicit security bypass marker found"
            )

        # Check for contradiction patterns (e.g., has decorator but explicitly skipped)
        if evidence.symbol_info and "auth" in evidence.snippet.lower():
            auth_count = evidence.snippet.lower().count("auth")
            skip_count = evidence.snippet.lower().count("skip")
            if auth_count > 0 and skip_count > 0:
                return ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="Security control present but contradicted"
                )

        # Default: UNKNOWN (not DISPROVEN)
        return ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="No explicit bypass markers found"
        )

    def _is_code_exec_sink(self, finding: Finding, evidence: EvidenceResult) -> Tuple[bool, str]:
        """
        Detect if finding involves exec/eval/compile sink within symbol range.

        Uses AST parsing when available (avoids comment false positives).
        Falls back to regex that handles line-number prefixes.

        Returns:
            (is_sink, reason) - reason explains what was detected
        """
        if not evidence.symbol_info:
            return (False, "No symbol info")

        symbol_name = evidence.symbol_info.name
        symbol_type = evidence.symbol_info.type

        # Try AST parsing first (most reliable)
        ast_parse_succeeded = False
        if evidence.snippet:
            try:
                tree = ast.parse(evidence.snippet)
                ast_parse_succeeded = True

                # Find the target symbol (function or class) in the AST
                target_node = None
                for node in ast.walk(tree):
                    if symbol_type == "function" and isinstance(node, ast.FunctionDef):
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

        # Only use regex fallback if AST parsing failed or couldn't find the symbol
        if not ast_parse_succeeded:
            # Regex fallback: search entire snippet (can't reliably scope with regex)
            # This is less precise but better than false negatives
            snippet = evidence.snippet or finding.code_snippet or ""

            for line in snippet.split('\n'):
                # Strip line-number prefix: "123: code" -> "code"
                clean_line = re.sub(r'^\s*\d+\s*:\s*', '', line)

                # Skip comment lines
                if re.match(r'^\s*#', clean_line):
                    continue

                # Check for exec/eval/compile calls
                if re.search(r'\b(exec|eval|compile)\s*\(', clean_line):
                    return (True, f"Code-exec sink: detected in snippet")

        return (False, "No exec/eval/compile sink detected")

    def _apply_rules(
        self,
        checklist: ProofChecklist,
        finding: Finding,
        evidence: EvidenceResult
    ) -> Disposition:
        """Apply strict disposition rules in priority order."""
        # Rule 1: VALID_SECURITY_ISSUE (all A-F PROVEN True)
        if all([
            checklist.source_controlled_input.status == ChecklistStatus.PROVEN and checklist.source_controlled_input.value,
            checklist.sink_present.status == ChecklistStatus.PROVEN and checklist.sink_present.value,
            checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN and checklist.dataflow_evidenced.value,
            checklist.reachable.status == ChecklistStatus.PROVEN and checklist.reachable.value,
            checklist.boundary_crossed.status == ChecklistStatus.PROVEN and checklist.boundary_crossed.value,
            checklist.not_only_misconfig.status == ChecklistStatus.PROVEN and checklist.not_only_misconfig.value,
        ]):
            return Disposition.VALID_SECURITY_ISSUE

        # Rule 2: BUG (security control bypassed + sink + reachable)
        if (checklist.security_control_bypassed and
                checklist.security_control_bypassed.status == ChecklistStatus.PROVEN and
                checklist.security_control_bypassed.value and
                checklist.sink_present.status == ChecklistStatus.PROVEN and
                checklist.sink_present.value and
                checklist.reachable.status == ChecklistStatus.PROVEN and
                checklist.reachable.value):
            return Disposition.BUG

        # Rule 3: MISCONFIGURATION (not_only_misconfig PROVEN False + others PROVEN True)
        if (checklist.not_only_misconfig.status == ChecklistStatus.PROVEN and
                not checklist.not_only_misconfig.value and
                checklist.sink_present.status == ChecklistStatus.PROVEN and
                checklist.sink_present.value and
                checklist.source_controlled_input.status == ChecklistStatus.PROVEN and
                checklist.source_controlled_input.value and
                checklist.reachable.status == ChecklistStatus.PROVEN and
                checklist.reachable.value and
                checklist.boundary_crossed.status == ChecklistStatus.PROVEN and
                checklist.boundary_crossed.value):
            return Disposition.MISCONFIGURATION

        # Rule 4: BY_DESIGN (code-exec features with conservative heuristics)
        # NEVER treat command injection as BY_DESIGN
        if self._is_product_feature(finding, evidence, checklist):
            return Disposition.BY_DESIGN

        # Rule 5: HARDENING (sink + (reachable OR source) but no dataflow)
        if (checklist.sink_present.status == ChecklistStatus.PROVEN and
                checklist.sink_present.value and
                (
                    (checklist.reachable.status == ChecklistStatus.PROVEN and checklist.reachable.value) or
                    (checklist.source_controlled_input.status == ChecklistStatus.PROVEN and checklist.source_controlled_input.value)
                ) and
                checklist.dataflow_evidenced.status != ChecklistStatus.PROVEN):
            return Disposition.HARDENING

        # Rule 6: SPECULATIVE (default)
        return Disposition.SPECULATIVE

    def _is_product_feature(
        self,
        finding: Finding,
        evidence: EvidenceResult,
        checklist: ProofChecklist
    ) -> bool:
        """Check if this is a BY_DESIGN product feature (conservative)."""
        # NEVER: Command injection is NEVER BY_DESIGN
        vuln_type_lower = finding.vulnerability_type.lower()
        if "command" in vuln_type_lower and "injection" in vuln_type_lower:
            return False

        # Check for code-exec features (exec/eval/kernel execute)
        code_exec_markers = ["exec", "eval", "compile", "kernel", "execute"]
        if not any(marker in vuln_type_lower for marker in code_exec_markers):
            return False

        # Check for product feature context (pipeline/connector/kernel)
        context = (finding.file_path + " " + finding.description).lower()
        product_contexts = [
            "pipeline", "executor", "kernel", "connector",
            "data_pipeline", "etl", "workflow", "dag"
        ]

        if not any(ctx in context for ctx in product_contexts):
            return False

        # Must NOT have user-controlled source
        if (checklist.source_controlled_input.status == ChecklistStatus.PROVEN and
                checklist.source_controlled_input.value):
            return False

        return True

    def _apply_pattern_downgrades(
        self,
        disposition: Disposition,
        finding: Finding,
        evidence: EvidenceResult,
        checklist: ProofChecklist,
        category: Optional[VulnerabilityCategory]
    ) -> Disposition:
        """Apply pattern-based downgrades (ONLY downgrades, never upgrades)."""
        # Pattern rules can ONLY return: SPECULATIVE, HARDENING, MISCONFIGURATION, BY_DESIGN
        # They MUST NEVER return: VALID_SECURITY_ISSUE or BUG

        # SSRF with constant URL
        if category == VulnerabilityCategory.SSRF and evidence.ssrf_analysis:
            if evidence.ssrf_analysis.url_is_constant:
                return Disposition.SPECULATIVE
            if evidence.ssrf_analysis.url_from_config:
                return Disposition.SPECULATIVE

        # CSWSH: check_origin alone without ambient creds
        if category == VulnerabilityCategory.CSWSH:
            if "check_origin" in evidence.snippet.lower():
                # If no evidence of session/cookie abuse
                if "cookie" not in evidence.snippet.lower() and "session" not in evidence.snippet.lower():
                    return Disposition.HARDENING

        # Deserialization without attacker source
        if category == VulnerabilityCategory.DESERIALIZATION:
            if (checklist.source_controlled_input.status != ChecklistStatus.PROVEN or
                    not checklist.source_controlled_input.value):
                return Disposition.HARDENING

        # Hardcoded secrets in test/example files
        if category == VulnerabilityCategory.HARDCODED_SECRET:
            if any(marker in finding.file_path.lower() for marker in [
                "test", "example", "sample", "demo", "docker-compose", ".env.example"
            ]):
                return Disposition.HARDENING

        # SQL injection in pipeline/connector without attacker source
        if category == VulnerabilityCategory.SQL_INJECTION:
            if any(marker in finding.file_path.lower() for marker in ["connector", "pipeline", "etl"]):
                if (checklist.source_controlled_input.status != ChecklistStatus.PROVEN or
                        not checklist.source_controlled_input.value):
                    return Disposition.BY_DESIGN

        return disposition

    def _compute_classification_confidence(
        self,
        disposition: Disposition,
        checklist: ProofChecklist
    ) -> int:
        """Compute confidence in classification (0-100)."""
        # Count proven items
        items = [
            checklist.source_controlled_input,
            checklist.sink_present,
            checklist.dataflow_evidenced,
            checklist.reachable,
            checklist.boundary_crossed,
            checklist.not_only_misconfig,
        ]

        proven_count = sum(1 for item in items if item.status == ChecklistStatus.PROVEN)
        total_items = len(items)

        base_confidence = int((proven_count / total_items) * 100)

        # Boost for VALID/BUG
        if disposition in [Disposition.VALID_SECURITY_ISSUE, Disposition.BUG]:
            return min(100, base_confidence + 10)

        # Reduce for SPECULATIVE
        if disposition == Disposition.SPECULATIVE:
            return max(0, base_confidence - 20)

        return base_confidence

    def _compute_exploit_confidence(self, checklist: ProofChecklist) -> int:
        """Compute confidence in exploitability (0-100), only for VALID/BUG."""
        # All A-F proven = high confidence
        items = [
            checklist.source_controlled_input,
            checklist.sink_present,
            checklist.dataflow_evidenced,
            checklist.reachable,
            checklist.boundary_crossed,
            checklist.not_only_misconfig,
        ]

        proven_and_true = sum(
            1 for item in items
            if item.status == ChecklistStatus.PROVEN and item.value
        )

        return int((proven_and_true / len(items)) * 100)

    def _generate_reasoning(
        self,
        disposition: Disposition,
        checklist: ProofChecklist,
        evidence: EvidenceResult,
        category: Optional[VulnerabilityCategory]
    ) -> list[str]:
        """Generate 2-4 reasoning bullets explaining the disposition."""
        bullets = []

        if disposition == Disposition.VALID_SECURITY_ISSUE:
            bullets.append("All six proof items verified: source, sink, dataflow, reachable, boundary, and exploitable in default config")
            if category:
                bullets.append(f"Category: {category.value}")

        elif disposition == Disposition.BUG:
            bullets.append("Security control explicitly bypassed in same scope")
            bullets.append(f"Reason: {checklist.security_control_bypassed.reason if checklist.security_control_bypassed else 'N/A'}")

        elif disposition == Disposition.HARDENING:
            bullets.append("Dangerous sink present but dataflow not proven")
            if checklist.source_controlled_input.status != ChecklistStatus.PROVEN:
                bullets.append("No clear attacker-controlled input source")

        elif disposition == Disposition.MISCONFIGURATION:
            bullets.append("Exploitable only when security explicitly disabled")
            bullets.append(f"Config dependency: {checklist.not_only_misconfig.reason}")

        elif disposition == Disposition.BY_DESIGN:
            bullets.append("Code execution feature in pipeline/kernel context")
            bullets.append("Developer-controlled input, not user-controlled")

        elif disposition == Disposition.SPECULATIVE:
            bullets.append("Insufficient evidence for classification")
            # List what's missing
            missing = []
            if checklist.source_controlled_input.status != ChecklistStatus.PROVEN:
                missing.append("source")
            if checklist.sink_present.status != ChecklistStatus.PROVEN:
                missing.append("sink")
            if checklist.dataflow_evidenced.status != ChecklistStatus.PROVEN:
                missing.append("dataflow")
            if checklist.reachable.status != ChecklistStatus.PROVEN:
                missing.append("reachability")

            if missing:
                bullets.append(f"Missing: {', '.join(missing)}")

        # Add symbol/framework context if available
        if evidence.symbol_info:
            bullets.append(f"Symbol: {evidence.symbol_info.name} ({evidence.symbol_info.type})")

        return bullets[:4]  # Limit to 4 bullets
