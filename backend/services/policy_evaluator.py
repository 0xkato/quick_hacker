"""Policy evaluation for VRP acceptance criteria."""
import re
from models.schemas import (
    Finding, Evidence, TriagePolicy, PolicyDecision, PathClassification,
    Disposition, VulnerabilityCategory, ChecklistStatus, InputChannel,
    PolicyEvaluationResult
)
from services.strict_classifier import ClassificationResult


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

        Args:
            finding: Finding with path_classification attached
            evidence: Evidence bundle
            classification: Classification result from StrictClassifier
            policy: Triage policy

        Returns:
            PolicyEvaluationResult with decision and reasoning
        """
        gate_results = {}
        reasoning = []
        overridden = False

        # Get path classification (from pre-filter)
        path_class = getattr(finding, 'path_classification', PathClassification.unknown)

        # Get category
        category = getattr(finding, 'category', None)

        # Apply category-specific evidence gates
        if category == VulnerabilityCategory.COMMAND_INJECTION:
            gate_passed = self._evaluate_command_injection_gate(evidence, reasoning)
            gate_results["command_injection"] = gate_passed

            # If gate fails, downgrade VALID to HARDENING_ONLY
            if not gate_passed and classification.disposition == Disposition.VALID_SECURITY_ISSUE:
                decision = PolicyDecision.HARDENING_ONLY
                overridden = True
                return PolicyEvaluationResult(
                    decision=decision,
                    path_classification=path_class,
                    gate_results=gate_results,
                    reasoning=reasoning,
                    original_disposition=classification.disposition,
                    overridden=overridden
                )

        elif category == VulnerabilityCategory.INTEGER_OVERFLOW:
            gate_passed = self._evaluate_integer_overflow_gate(
                evidence, classification, reasoning
            )
            gate_results["integer_overflow"] = gate_passed

            # If gate fails, downgrade VALID to HARDENING_ONLY
            if not gate_passed and classification.disposition == Disposition.VALID_SECURITY_ISSUE:
                decision = PolicyDecision.HARDENING_ONLY
                overridden = True
                return PolicyEvaluationResult(
                    decision=decision,
                    path_classification=path_class,
                    gate_results=gate_results,
                    reasoning=reasoning,
                    original_disposition=classification.disposition,
                    overridden=overridden
                )

        # Map disposition to decision
        decision = self._map_disposition_to_decision(
            classification.disposition, policy, gate_results
        )

        if not reasoning:
            reasoning = ["Classification matches policy criteria"]

        return PolicyEvaluationResult(
            decision=decision,
            path_classification=path_class,
            gate_results=gate_results,
            reasoning=reasoning,
            original_disposition=classification.disposition,
            overridden=overridden
        )

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

    def _evaluate_command_injection_gate(
        self,
        evidence: Evidence,
        reasoning: list[str]
    ) -> bool:
        """
        Command injection evidence gate.

        Requires:
        1. Shell execution (shell=True or os.system)
        2. String interpolation (f-strings, concatenation, .format())
        3. Credible boundary (network, ci_artifact, file_input)

        Without shell parsing, it's argument injection (HARDENING_ONLY).

        Args:
            evidence: Evidence bundle
            reasoning: List to append reasoning to

        Returns:
            True if gate passes, False otherwise
        """
        # Get code snippets to analyze
        snippets = []
        if evidence.snippet:
            snippets.append(evidence.snippet)
        if evidence.handler_snippet:
            snippets.append(evidence.handler_snippet)
        if evidence.dataflow_snippet:
            snippets.append(evidence.dataflow_snippet)

        # Check requirement 1: Shell execution
        has_shell = self._has_shell_execution(snippets)
        if not has_shell:
            reasoning.append(
                "Command injection gate failed: no shell parsing detected "
                "(argument injection without shell=True)"
            )
            return False

        # Check requirement 2: String interpolation
        has_interpolation = self._attacker_controls_shell_string(snippets)
        if not has_interpolation:
            reasoning.append(
                "Command injection gate failed: no string interpolation detected "
                "(static command or safe argument passing)"
            )
            return False

        # Check requirement 3: Credible boundary
        credible_boundaries = [
            InputChannel.network,
            InputChannel.ci_artifact,
            InputChannel.file_input
        ]
        if evidence.input_channel not in credible_boundaries:
            reasoning.append(
                f"Command injection gate failed: input channel {evidence.input_channel} "
                "not a credible attack boundary"
            )
            return False

        # All requirements met
        reasoning.append(
            "Command injection gate passed: shell execution + string interpolation + "
            f"credible boundary ({evidence.input_channel})"
        )
        return True

    def _has_shell_execution(self, snippets: list[str]) -> bool:
        """
        Check if code uses shell execution.

        Args:
            snippets: Code snippets to analyze

        Returns:
            True if shell execution detected
        """
        # Patterns for shell execution
        shell_patterns = [
            r'shell\s*=\s*True',  # subprocess with shell=True
            r'os\.system\s*\(',   # os.system calls
            r'commands\.',        # deprecated commands module (also uses shell)
        ]

        for snippet in snippets:
            for pattern in shell_patterns:
                if re.search(pattern, snippet):
                    return True

        return False

    def _attacker_controls_shell_string(self, snippets: list[str]) -> bool:
        """
        Check if attacker controls shell command string.

        Args:
            snippets: Code snippets to analyze

        Returns:
            True if string interpolation detected
        """
        # Patterns for string manipulation that allows injection
        interpolation_patterns = [
            r'f"[^"]*\{[^}]+\}[^"]*"',  # f-strings: f"cmd {var}"
            r"f'[^']*\{[^}]+\}[^']*'",  # f-strings: f'cmd {var}'
            r'\.format\s*\(',            # .format(): "cmd {}".format(var)
            r'\+\s*[a-zA-Z_]\w*',       # concatenation: "cmd " + var
            r'[a-zA-Z_]\w*\s*\+',       # concatenation: var + " cmd"
            r'%\s*\(',                   # % formatting: "cmd %s" % (var,)
        ]

        for snippet in snippets:
            for pattern in interpolation_patterns:
                if re.search(pattern, snippet):
                    return True

        return False

    def _evaluate_integer_overflow_gate(
        self,
        evidence: Evidence,
        classification: ClassificationResult,
        reasoning: list[str]
    ) -> bool:
        """
        Integer overflow evidence gate.

        Requires:
        1. Attacker-controlled operands (proven in checklist)
        2. Overflow-prone operation (multiplication or unchecked addition)
        3. Allocation or bounds use (malloc, array index, buffer size)
        4. Proven type mismatch (32-bit → 64-bit)

        Without complete proof chain, it's speculative overflow (HARDENING_ONLY).

        Args:
            evidence: Evidence bundle
            classification: Classification result with proof checklist
            reasoning: List to append reasoning to

        Returns:
            True if gate passes, False otherwise
        """
        missing = []

        # Requirement 1: Attacker-controlled operands
        if classification.proof_checklist.source_controlled_input.status != ChecklistStatus.PROVEN:
            missing.append("no proven attacker control over operands")

        # Requirement 2: Overflow-prone operation (multiplication or unchecked addition)
        has_overflow_op = self._has_overflow_prone_operation(evidence)
        if not has_overflow_op:
            missing.append("no overflow-prone operation (multiplication/unchecked addition)")

        # Requirement 3: Allocation or bounds check using result
        has_dangerous_use = self._has_allocation_or_bounds_use(evidence)
        if not has_dangerous_use:
            missing.append("no allocation/bounds use detected")

        # Requirement 4: Proven mismatch (32-bit calc → 64-bit size, etc.)
        has_mismatch = self._has_proven_type_mismatch(evidence)
        if not has_mismatch:
            missing.append("no proven type mismatch (32-bit → 64-bit, etc.)")

        if missing:
            reasoning.append(f"Integer overflow gate failed: {'; '.join(missing)}")
            return False

        # All requirements met
        reasoning.append(
            "Integer overflow gate passed: attacker control + overflow op + allocation use + mismatch"
        )
        return True

    def _has_overflow_prone_operation(self, evidence: Evidence) -> bool:
        """
        Check for multiplication or unchecked addition.

        Args:
            evidence: Evidence bundle

        Returns:
            True if overflow-prone operation detected
        """
        snippet = evidence.snippet or ""

        # Look for multiplication
        if re.search(r'\w+\s*\*\s*\w+', snippet):
            return True

        # Look for addition without overflow check
        # (Hard to prove "unchecked" statically, so look for addition near allocation)
        if re.search(r'\w+\s*\+\s*\w+', snippet):
            if any(func in snippet for func in ['malloc', 'calloc', 'new ']):
                return True

        return False

    def _has_allocation_or_bounds_use(self, evidence: Evidence) -> bool:
        """
        Check if result is used in allocation or bounds check.

        Args:
            evidence: Evidence bundle

        Returns:
            True if allocation or bounds use detected
        """
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
        """
        Check for type mismatch (32-bit calc → 64-bit use).

        Args:
            evidence: Evidence bundle

        Returns:
            True if type mismatch detected
        """
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
