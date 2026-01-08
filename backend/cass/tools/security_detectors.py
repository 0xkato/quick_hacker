"""Security detection tools for CASS agent."""

import re
from pathlib import Path


# Secret detection patterns: (pattern, type)
SECRET_PATTERNS = [
    # API keys and tokens
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "api_key"),
    (r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "secret_key"),
    (r"(?i)(access[_-]?token|accesstoken)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "access_token"),
    (r"(?i)(auth[_-]?token|authtoken)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "auth_token"),
    (r"(?i)(bearer[_-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "bearer_token"),
    # AWS credentials
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*['\"]([A-Z0-9]{16,})['\"]", "aws_key"),
    (r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['\"]([^'\"]{20,})['\"]", "aws_secret"),
    # Database URLs with credentials
    (r"(?i)(database[_-]?url|db[_-]?url)\s*[=:]\s*['\"]([^'\"]*://[^'\"]*:[^'\"]*@[^'\"]+)['\"]", "database_url"),
    (r"(?i)(postgres|mysql|mongodb)://[^'\"]+:[^'\"]+@[^'\"]+", "database_url"),
    # Private keys
    (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]([^'\"]{16,})['\"]", "private_key"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "private_key_pem"),
    # GitHub/GitLab tokens
    (r"ghp_[a-zA-Z0-9]{36}", "github_token"),
    (r"glpat-[a-zA-Z0-9\-]{20,}", "gitlab_token"),
    # Generic patterns
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]", "password"),
    (r"sk-[a-zA-Z0-9]{20,}", "openai_key"),
]

# Dangerous sink patterns by language and type
SINK_PATTERNS = {
    "python": {
        "sql": [
            r"\.execute\s*\(\s*[\"'].*\{.*\}.*[\"']\.format",
            r"\.execute\s*\(\s*f[\"']",
            r"\.execute\s*\(\s*[^,]+\s*\+\s*",
            r"cursor\.execute\s*\(",
            r"db\.execute\s*\(",
            r"\.raw\s*\(",  # Django raw SQL
        ],
        "command": [
            r"subprocess\.call\s*\([^)]*shell\s*=\s*True",
            r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True",
            r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "file": [
            r"open\s*\(\s*[^,)]+\s*,\s*['\"]w",
            r"open\s*\(\s*[^,)]+\s*,\s*['\"]a",
            r"Path\s*\([^)]+\)\.write",
            r"shutil\.copy\s*\(",
            r"shutil\.move\s*\(",
        ],
        "ssrf": [
            r"requests\.(get|post|put|delete|patch)\s*\(",
            r"urllib\.request\.urlopen\s*\(",
            r"httpx\.(get|post|put|delete|patch)\s*\(",
            r"aiohttp\.ClientSession\s*\(",
        ],
    },
    "javascript": {
        "sql": [
            r"\.query\s*\(\s*[`'\"].*\$\{",
            r"\.query\s*\(\s*[^,]+\s*\+\s*",
            r"\.execute\s*\(\s*[`'\"].*\$\{",
        ],
        "command": [
            r"child_process\.exec\s*\(",
            r"child_process\.execSync\s*\(",
            r"child_process\.spawn\s*\(",
            r"eval\s*\(",
            r"new\s+Function\s*\(",
        ],
        "file": [
            r"fs\.writeFileSync\s*\(",
            r"fs\.writeFile\s*\(",
            r"fs\.appendFileSync\s*\(",
        ],
        "ssrf": [
            r"fetch\s*\(",
            r"axios\.(get|post|put|delete|patch)\s*\(",
            r"request\s*\(",
        ],
    },
    "c": {
        "command": [
            r"system\s*\(",
            r"popen\s*\(",
            r"exec[lv]p?\s*\(",
        ],
    },
    "go": {
        "sql": [
            r"db\.Query\s*\(",
            r"db\.Exec\s*\(",
            r"\.QueryRow\s*\(",
        ],
        "command": [
            r"exec\.Command\s*\(",
            r"os\.Exec\s*\(",
        ],
    },
}

# Memory safety issue patterns for C/C++
MEMORY_PATTERNS = {
    "buffer_overflow": [
        r"strcpy\s*\(",
        r"strcat\s*\(",
        r"sprintf\s*\(",
        r"gets\s*\(",
        r"scanf\s*\([^,]*%s",
    ],
    "use_after_free": [
        r"free\s*\([^)]+\)\s*;[^}]*\*\s*\w+",  # free followed by dereference
    ],
    "double_free": [
        r"free\s*\(\s*(\w+)\s*\).*free\s*\(\s*\1\s*\)",
    ],
    "memory_leak": [
        r"malloc\s*\([^)]+\)\s*;(?![^}]*free)",
    ],
    "null_pointer": [
        r"(\w+)\s*=\s*NULL.*\*\s*\1",
    ],
    "format_string": [
        r"printf\s*\(\s*\w+\s*\)",  # printf with variable as format
        r"sprintf\s*\([^,]+,\s*\w+\s*\)",
    ],
}

# Input vector patterns for finding user input sources
INPUT_PATTERNS = {
    "python": [
        (r"request\.(args|form|json|data|files|values|cookies|headers)", "http_input"),
        (r"input\s*\(", "stdin"),
        (r"sys\.argv", "command_line"),
        (r"os\.environ", "environment"),
    ],
    "javascript": [
        (r"req\.(body|params|query|cookies|headers)", "http_input"),
        (r"process\.argv", "command_line"),
        (r"process\.env", "environment"),
        (r"document\.location", "client_input"),
        (r"window\.location", "client_input"),
    ],
}

# Authentication and authorization patterns
AUTH_PATTERNS = {
    "authentication": [
        (r"(?i)def\s+(login|authenticate|sign_?in|verify_?user)", "auth_function"),
        (r"(?i)@login_required", "auth_decorator"),
        (r"(?i)@requires_auth", "auth_decorator"),
        (r"(?i)jwt\.decode", "jwt_auth"),
        (r"(?i)verify_?password", "password_verify"),
        (r"(?i)check_?password", "password_verify"),
        (r"(?i)bcrypt\.(compare|check)", "password_verify"),
    ],
    "authorization": [
        (r"(?i)@requires_?role", "role_check"),
        (r"(?i)@permission_?required", "permission_check"),
        (r"(?i)has_?permission", "permission_check"),
        (r"(?i)is_?admin", "admin_check"),
        (r"(?i)can_?(access|view|edit|delete)", "access_control"),
        (r"(?i)check_?access", "access_control"),
    ],
    "session": [
        (r"(?i)session\[", "session_access"),
        (r"(?i)flask\.session", "session_access"),
        (r"(?i)request\.session", "session_access"),
    ],
}

# Language extensions mapping
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",  # TypeScript uses similar patterns
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".go": "go",
    ".c": "c",
    ".cpp": "c",  # C++ uses similar patterns to C
    ".h": "c",
    ".hpp": "c",
}


class SecurityDetectors:
    """Tools for detecting security issues in code."""

    def __init__(self, repo_path: str):
        """Initialize with repository path.

        Args:
            repo_path: Path to the repository root.
        """
        self.repo_path = Path(repo_path).resolve()

    def _get_all_files(self) -> list[Path]:
        """Get all relevant files in the repository."""
        files = []
        ignore_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build"}

        for file_path in self.repo_path.rglob("*"):
            if file_path.is_file():
                # Skip files in ignored directories
                if any(ignored in file_path.parts for ignored in ignore_dirs):
                    continue
                files.append(file_path)

        return files

    def _read_file_safe(self, path: Path) -> str:
        """Read file contents safely."""
        try:
            return path.read_text(errors="replace")
        except Exception:
            return ""

    def _get_language(self, file_path: Path) -> str | None:
        """Get the language for a file based on extension."""
        return LANGUAGE_EXTENSIONS.get(file_path.suffix.lower())

    def find_secrets(self, path: str = ".") -> list[dict]:
        """Find hardcoded secrets in the codebase.

        Args:
            path: Relative path within repo to search (default: root).

        Returns:
            List of dicts with: type, name, file, line, value_preview.
        """
        search_path = (self.repo_path / path).resolve()
        secrets = []

        for file_path in self._get_all_files():
            if not str(file_path).startswith(str(search_path)):
                continue

            content = self._read_file_safe(file_path)
            if not content:
                continue

            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                for pattern, secret_type in SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        # Extract the variable name if available
                        name = match.group(1) if match.lastindex and match.lastindex >= 1 else secret_type
                        # Get value preview (masked)
                        full_match = match.group(0)
                        preview = full_match[:20] + "..." if len(full_match) > 20 else full_match

                        secrets.append({
                            "type": secret_type,
                            "name": str(name).upper() if isinstance(name, str) else secret_type,
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": line_num,
                            "value_preview": preview,
                            "code": line.strip()[:100],
                        })
                        break  # Only report first match per line

        return secrets

    def find_sinks(self, path: str = ".") -> list[dict]:
        """Find dangerous sinks (SQL, command, file, SSRF).

        Args:
            path: Relative path within repo to search (default: root).

        Returns:
            List of dicts with: type, file, line, code, language.
        """
        search_path = (self.repo_path / path).resolve()
        sinks = []

        for file_path in self._get_all_files():
            if not str(file_path).startswith(str(search_path)):
                continue

            language = self._get_language(file_path)
            if not language or language not in SINK_PATTERNS:
                continue

            content = self._read_file_safe(file_path)
            if not content:
                continue

            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                for sink_type, patterns in SINK_PATTERNS[language].items():
                    for pattern in patterns:
                        if re.search(pattern, line):
                            sinks.append({
                                "type": sink_type,
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": line_num,
                                "code": line.strip()[:100],
                                "language": language,
                                "pattern": pattern,
                            })
                            break  # Only report first pattern match per sink type per line
                    else:
                        continue
                    break  # Found a sink type match, don't check other types for this line

        return sinks

    def find_memory_issues(self, path: str = ".") -> list[dict]:
        """Find memory safety issues in C/C++ code.

        Args:
            path: Relative path within repo to search (default: root).

        Returns:
            List of dicts with: type, file, line, code, severity.
        """
        search_path = (self.repo_path / path).resolve()
        issues = []

        severity_map = {
            "buffer_overflow": "high",
            "use_after_free": "critical",
            "double_free": "critical",
            "memory_leak": "medium",
            "null_pointer": "high",
            "format_string": "high",
        }

        for file_path in self._get_all_files():
            if not str(file_path).startswith(str(search_path)):
                continue

            # Only check C/C++ files
            if file_path.suffix.lower() not in [".c", ".cpp", ".h", ".hpp", ".cc", ".cxx"]:
                continue

            content = self._read_file_safe(file_path)
            if not content:
                continue

            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                for issue_type, patterns in MEMORY_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                "type": issue_type,
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": line_num,
                                "code": line.strip()[:100],
                                "severity": severity_map.get(issue_type, "medium"),
                            })
                            break  # Only report first pattern match per issue type
                    else:
                        continue
                    break  # Found an issue type match

        return issues

    def find_input_vectors(self, path: str = ".") -> list[dict]:
        """Find user input sources (HTTP, stdin, env, etc.).

        Args:
            path: Relative path within repo to search (default: root).

        Returns:
            List of dicts with: type, source, file, line, code.
        """
        search_path = (self.repo_path / path).resolve()
        inputs = []

        for file_path in self._get_all_files():
            if not str(file_path).startswith(str(search_path)):
                continue

            language = self._get_language(file_path)
            if not language or language not in INPUT_PATTERNS:
                continue

            content = self._read_file_safe(file_path)
            if not content:
                continue

            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                for pattern, input_type in INPUT_PATTERNS[language]:
                    if re.search(pattern, line):
                        inputs.append({
                            "type": input_type,
                            "source": pattern,
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": line_num,
                            "code": line.strip()[:100],
                            "language": language,
                        })
                        break  # Only report first match per line

        return inputs

    def find_auth_patterns(self, path: str = ".") -> list[dict]:
        """Find authentication and authorization patterns.

        Args:
            path: Relative path within repo to search (default: root).

        Returns:
            List of dicts with: category, type, file, line, code.
        """
        search_path = (self.repo_path / path).resolve()
        patterns = []

        for file_path in self._get_all_files():
            if not str(file_path).startswith(str(search_path)):
                continue

            # Check common source file types
            if file_path.suffix.lower() not in [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb"]:
                continue

            content = self._read_file_safe(file_path)
            if not content:
                continue

            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                for category, category_patterns in AUTH_PATTERNS.items():
                    for pattern, auth_type in category_patterns:
                        if re.search(pattern, line):
                            patterns.append({
                                "category": category,
                                "type": auth_type,
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": line_num,
                                "code": line.strip()[:100],
                            })
                            break  # Only report first match per category per line
                    else:
                        continue
                    break  # Found a category match

        return patterns
