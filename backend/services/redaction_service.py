"""
Redaction service for sensitive data in evidence snippets.

Optional: Toggle via TRIAGE_ENABLE_REDACTION env var.
"""

import re
from typing import Pattern


class RedactionService:
    """
    Redact secrets and sensitive data from evidence snippets.

    Uses precompiled regex patterns for performance.
    """

    def __init__(self):
        self.patterns: list[tuple[Pattern, str]] = [
            # API Keys
            (re.compile(r'sk-[a-zA-Z0-9]{20,}', re.IGNORECASE), '[REDACTED_API_KEY]'),
            (re.compile(r'Bearer\s+[a-zA-Z0-9\-_\.]+', re.IGNORECASE), 'Bearer [REDACTED_TOKEN]'),

            # AWS Keys
            (re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE), '[REDACTED_AWS_KEY]'),
            (re.compile(r'aws_secret_access_key\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
             'aws_secret_access_key="[REDACTED]"'),

            # GitHub Tokens
            (re.compile(r'gh[ps]_[a-zA-Z0-9]{36}', re.IGNORECASE), '[REDACTED_GITHUB_TOKEN]'),

            # Generic tokens/secrets
            (re.compile(r'(token|secret|password|api_key)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]', re.IGNORECASE),
             r'\1="[REDACTED]"'),

            # JWT tokens
            (re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'), '[REDACTED_JWT]'),

            # Private keys
            (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                       re.IGNORECASE), '[REDACTED_PRIVATE_KEY]'),

            # Database URLs with passwords
            (re.compile(r'(postgres|mysql|mongodb)://[^:]+:([^@]+)@', re.IGNORECASE),
             r'\1://[REDACTED]:[REDACTED]@'),

            # Email addresses (optional, might be too aggressive)
            # (re.compile(r'[\w\.-]+@[\w\.-]+\.\w+'), '[REDACTED_EMAIL]'),
        ]

    def redact(self, text: str) -> str:
        """
        Redact sensitive data from text.

        Args:
            text: Input text potentially containing secrets

        Returns:
            Text with secrets redacted
        """
        if not text:
            return text

        redacted = text
        for pattern, replacement in self.patterns:
            redacted = pattern.sub(replacement, redacted)

        return redacted

    def redact_multiple(self, texts: list[str]) -> list[str]:
        """Redact multiple text strings."""
        return [self.redact(text) for text in texts]


# Singleton instance
redaction_service = RedactionService()
