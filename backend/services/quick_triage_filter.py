"""Quick Triage Filter - Immediate false positive detection at report time.

This filter runs synchronously when a finding is reported (not as a separate LLM call).
It catches obvious false positives based on code patterns before findings are stored.

Key checks:
1. Security controls present (bounds checks, validation, sanitization)
2. Test/dev/example code paths
3. Framework protections in use
4. Speculative attack scenarios
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class QuickTriageResult:
    """Result of quick triage filter."""
    should_filter: bool
    reason: str
    filter_category: str  # "control_present", "test_code", "framework_protected", "speculative"


class QuickTriageFilter:
    """Lightweight filter for obvious false positives.

    This runs synchronously at report time - no LLM calls, just pattern matching.
    """

    # Test/dev/example path patterns
    TEST_PATH_PATTERNS = [
        r'/tests?/',
        r'/__tests__/',
        r'/spec/',
        r'/fixtures/',
        r'/mocks?/',
        r'/examples?/',
        r'/samples?/',
        r'/demo/',
        r'/seeders?/',
        r'_test\.',
        r'\.test\.',
        r'_spec\.',
        r'\.spec\.',
        r'test_[^/]+\.',
        r'/node_modules/',
        r'/vendor/',
        r'/third_party/',
        r'/\.bundle/',
    ]

    # Patterns that indicate bounds checking / length validation
    BOUNDS_CHECK_PATTERNS = [
        # C/C++ bounded functions
        r'strncpy\s*\(',
        r'strlcpy\s*\(',
        r'snprintf\s*\(',
        r'strncmp\s*\(',
        r'strncat\s*\(',
        r'memcpy\s*\([^,]+,\s*[^,]+,\s*(sizeof|MIN|min|MAX_|BUFFER_SIZE|_SIZE)',
        # Length checks
        r'if\s*\(\s*(strlen|len|length|size)\s*[<>=]',
        r'if\s*\(\s*\w+\s*[<>=]+\s*(MAX_|MIN_|BUFFER_|_SIZE|_LEN)',
        r'(MAX_SIZE|BUFFER_SIZE|MAX_LEN|_BUFF_SIZE)\s*-\s*1',
        # Array bounds
        r'if\s*\(\s*\w+\s*[<>]=?\s*(ARRAY_SIZE|arr_len|array_len)',
        r'if\s*\(\s*(index|idx|i)\s*[<>]=?\s*\w+\.(length|len|size)',
    ]

    # Patterns that indicate sanitization/validation
    SANITIZATION_PATTERNS = [
        # SQL parameterization
        r'execute\s*\(\s*["\'][^"\']*\?\s*["\']',  # ? placeholders
        r'execute\s*\(\s*["\'][^"\']*%s',  # %s placeholders
        r'\.objects\.(filter|get|exclude)\(',  # Django ORM
        r'select\(.*\)\.where\(',  # SQLAlchemy style
        r'query\s*\(\s*[^,]+,\s*\[',  # Parameterized with array
        # XSS escaping
        r'html\.escape\(',
        r'escape_html\(',
        r'encodeURIComponent\(',
        r'sanitize\(',
        r'DOMPurify',
        # Path sanitization
        r'os\.path\.basename\(',
        r'path\.basename\(',
        r'realpath\(',
        r'normpath\(',
        # Command injection
        r'subprocess\.[^(]+\([^)]*shell\s*=\s*False',
        r'subprocess\.run\s*\(\s*\[',  # List form = no shell
        r'execvp?\s*\(',  # execv uses argv array
    ]

    # Patterns in attack scenarios that indicate speculation
    SPECULATIVE_PHRASES = [
        r'if\s+(the\s+)?attacker\s+(can\s+)?bypass',
        r'if\s+validation\s+is\s+disabled',
        r'if\s+(the\s+)?length\s+check\s+is\s+(bypassed|circumvented|evaded)',
        r'assuming\s+(no\s+)?sanitization',
        r'assuming\s+validation\s+(is\s+)?disabled',
        r'if\s+(the\s+)?bounds?\s+check\s+(is\s+)?bypassed',
        r'could\s+potentially\s+be\s+exploited\s+if',
        r'if\s+(the\s+)?control\s+(is\s+)?evaded',
        r'when\s+security\s+(is\s+)?disabled',
    ]

    # Framework protection patterns
    FRAMEWORK_PROTECTED = [
        # React/Angular/Vue auto-escaping
        (r'\.(jsx|tsx)$', 'React JSX auto-escapes by default'),
        (r'\.vue$', 'Vue templates auto-escape by default'),
        (r'angular', 'Angular templates auto-escape by default'),
        # Django templates
        (r'\.html$.*\{\{', 'Django/Jinja2 templates auto-escape by default'),
        # Rust memory safety
        (r'\.rs$', 'Rust borrow checker provides memory safety'),
    ]

    def __init__(self):
        # Compile patterns for efficiency
        self._test_patterns = [re.compile(p, re.IGNORECASE) for p in self.TEST_PATH_PATTERNS]
        self._bounds_patterns = [re.compile(p, re.IGNORECASE) for p in self.BOUNDS_CHECK_PATTERNS]
        self._sanitization_patterns = [re.compile(p, re.IGNORECASE) for p in self.SANITIZATION_PATTERNS]
        self._speculative_patterns = [re.compile(p, re.IGNORECASE) for p in self.SPECULATIVE_PHRASES]

    def check(
        self,
        file_path: str,
        vulnerable_code: str,
        description: str,
        attack_scenario: Optional[str],
        vulnerability_type: str,
    ) -> Optional[QuickTriageResult]:
        """Run quick triage checks on a finding.

        Args:
            file_path: Path to the vulnerable file
            vulnerable_code: The code snippet
            description: Finding description
            attack_scenario: Optional attack scenario text
            vulnerability_type: Type of vulnerability

        Returns:
            QuickTriageResult if finding should be filtered, None to keep
        """
        # Check 1: Test/dev/example code path
        result = self._check_test_path(file_path)
        if result:
            return result

        # Check 2: Bounds checking / length validation present in code
        result = self._check_bounds_present(vulnerable_code, vulnerability_type)
        if result:
            return result

        # Check 3: Sanitization/validation present in code
        result = self._check_sanitization_present(vulnerable_code, vulnerability_type)
        if result:
            return result

        # Check 4: Speculative language in description or attack scenario
        text_to_check = description
        if attack_scenario:
            text_to_check += " " + attack_scenario
        result = self._check_speculative_language(text_to_check)
        if result:
            return result

        # No obvious false positive detected
        return None

    def _check_test_path(self, file_path: str) -> Optional[QuickTriageResult]:
        """Check if file is in test/dev/example path."""
        for pattern in self._test_patterns:
            if pattern.search(file_path):
                return QuickTriageResult(
                    should_filter=True,
                    reason=f"File appears to be test/dev/example code: {file_path}",
                    filter_category="test_code"
                )
        return None

    def _check_bounds_present(
        self,
        code: str,
        vuln_type: str
    ) -> Optional[QuickTriageResult]:
        """Check if bounds checking is present for memory safety issues."""
        # Only relevant for memory safety vulnerabilities
        memory_vulns = ['buffer_overflow', 'heap_overflow', 'stack_overflow',
                       'out_of_bounds', 'memory_corruption', 'integer_overflow']

        if not any(v in vuln_type.lower() for v in memory_vulns):
            return None

        for pattern in self._bounds_patterns:
            if pattern.search(code):
                match = pattern.search(code)
                return QuickTriageResult(
                    should_filter=True,
                    reason=f"Bounds checking appears present in code: {match.group(0)[:50]}",
                    filter_category="control_present"
                )
        return None

    def _check_sanitization_present(
        self,
        code: str,
        vuln_type: str
    ) -> Optional[QuickTriageResult]:
        """Check if sanitization is present for injection issues."""
        for pattern in self._sanitization_patterns:
            if pattern.search(code):
                match = pattern.search(code)
                return QuickTriageResult(
                    should_filter=True,
                    reason=f"Sanitization/protection appears present: {match.group(0)[:50]}",
                    filter_category="control_present"
                )
        return None

    def _check_speculative_language(self, text: str) -> Optional[QuickTriageResult]:
        """Check for speculative language indicating assumed bypass."""
        for pattern in self._speculative_patterns:
            if pattern.search(text):
                match = pattern.search(text)
                return QuickTriageResult(
                    should_filter=True,
                    reason=f"Attack scenario assumes bypassing existing control: '{match.group(0)}'",
                    filter_category="speculative"
                )
        return None


# Singleton instance
quick_triage_filter = QuickTriageFilter()
