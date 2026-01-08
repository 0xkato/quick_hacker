"""Framework detection and route parsing tools for CASS agent."""

import re
from pathlib import Path


# Framework detection patterns
FRAMEWORK_PATTERNS = {
    "backend": {
        "flask": [
            r"flask[=<>~]",
            r"from flask import",
            r"import flask",
        ],
        "fastapi": [
            r"fastapi[=<>~]",
            r"from fastapi import",
            r"import fastapi",
        ],
        "django": [
            r"django[=<>~]",
            r"from django",
            r"import django",
        ],
        "express": [
            r'"express"',
            r"require\(['\"]express['\"]\)",
            r"from ['\"]express['\"]",
        ],
        "rails": [
            r"gem ['\"]rails['\"]",
            r"Rails\.application",
        ],
        "spring": [
            r"spring-boot",
            r"@SpringBootApplication",
            r"org\.springframework",
        ],
    },
    "frontend": {
        "react": [
            r'"react"',
            r"from ['\"]react['\"]",
            r"import React",
        ],
        "vue": [
            r'"vue"',
            r"from ['\"]vue['\"]",
            r"createApp",
        ],
        "angular": [
            r'"@angular/core"',
            r"from ['\"]@angular",
        ],
        "nextjs": [
            r'"next"',
            r"from ['\"]next",
        ],
        "svelte": [
            r'"svelte"',
            r"from ['\"]svelte['\"]",
        ],
    },
    "orm": {
        "sqlalchemy": [
            r"sqlalchemy[=<>~]",
            r"from sqlalchemy",
        ],
        "prisma": [
            r'"@prisma/client"',
            r"from ['\"]@prisma",
        ],
        "typeorm": [
            r'"typeorm"',
            r"from ['\"]typeorm['\"]",
        ],
        "django_orm": [
            r"from django\.db import models",
            r"models\.Model",
        ],
        "sequelize": [
            r'"sequelize"',
            r"require\(['\"]sequelize['\"]\)",
        ],
    },
    "auth": {
        "passport": [
            r'"passport"',
            r"require\(['\"]passport['\"]\)",
        ],
        "jwt": [
            r"pyjwt[=<>~]",
            r"jsonwebtoken",
            r"from jwt import",
        ],
        "oauth": [
            r"oauth",
            r"OAuth",
        ],
    },
}

# Language extensions mapping
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sol": "solidity",
}


class FrameworkParsers:
    """Tools for detecting frameworks and parsing routes."""

    def __init__(self, repo_path: str):
        """Initialize with repository path."""
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

    def detect_frameworks(self) -> dict[str, list[str]]:
        """Detect frameworks used in the repository.

        Returns:
            dict with categories (backend, frontend, orm, auth) mapping to lists of detected frameworks.
        """
        detected = {
            "backend": [],
            "frontend": [],
            "orm": [],
            "auth": [],
        }

        # Collect all file contents for searching
        all_content = ""
        for file_path in self._get_all_files():
            # Only check relevant files
            if file_path.suffix in [".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".txt", ".toml", ".yaml", ".yml", ".rb", ".java", ".go"]:
                all_content += self._read_file_safe(file_path) + "\n"

        # Check each framework category
        for category, frameworks in FRAMEWORK_PATTERNS.items():
            for framework, patterns in frameworks.items():
                for pattern in patterns:
                    if re.search(pattern, all_content, re.IGNORECASE):
                        if framework not in detected[category]:
                            detected[category].append(framework)
                        break  # Found this framework, move to next

        return detected

    def detect_languages(self) -> dict[str, int]:
        """Detect programming languages and their file counts.

        Returns:
            dict mapping language names to file counts.
        """
        language_counts = {}

        for file_path in self._get_all_files():
            ext = file_path.suffix.lower()
            if ext in LANGUAGE_EXTENSIONS:
                lang = LANGUAGE_EXTENSIONS[ext]
                language_counts[lang] = language_counts.get(lang, 0) + 1

        return language_counts

    def parse_routes(self) -> list[dict]:
        """Parse HTTP routes from the codebase.

        Detects frameworks and calls appropriate parser.

        Returns:
            list of route dictionaries with path, method, handler, file, line, framework.
        """
        routes = []
        frameworks = self.detect_frameworks()

        # Parse based on detected frameworks
        if "flask" in frameworks["backend"]:
            routes.extend(self._parse_flask_routes())

        if "fastapi" in frameworks["backend"]:
            routes.extend(self._parse_fastapi_routes())

        if "django" in frameworks["backend"]:
            routes.extend(self._parse_django_routes())

        if "express" in frameworks["backend"]:
            routes.extend(self._parse_express_routes())

        return routes

    def _parse_flask_routes(self) -> list[dict]:
        """Parse Flask @app.route decorators.

        Returns:
            list of route dicts with path, methods, handler, file, line, framework.
        """
        routes = []

        # Pattern for Flask route decorators
        # Matches: @app.route('/path', methods=['GET', 'POST'])
        # or: @app.route('/path')
        # or: @bp.route('/path', methods=['GET'])
        route_pattern = re.compile(
            r"@\w+\.route\(\s*['\"]([^'\"]+)['\"]"  # Path
            r"(?:.*?methods\s*=\s*\[([^\]]+)\])?"   # Optional methods
            r"[^)]*\)\s*\n"                         # End of decorator
            r"\s*(?:async\s+)?def\s+(\w+)",         # Function name
            re.MULTILINE | re.DOTALL
        )

        for file_path in self._get_all_files():
            if file_path.suffix != ".py":
                continue

            content = self._read_file_safe(file_path)
            if not content or "@" not in content or "route" not in content:
                continue

            for match in route_pattern.finditer(content):
                path = match.group(1)
                methods_str = match.group(2)
                handler = match.group(3)

                # Parse methods
                if methods_str:
                    methods = [m.strip().strip("'\"") for m in methods_str.split(",")]
                else:
                    methods = ["GET"]

                # Find line number
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1

                routes.append({
                    "path": path,
                    "method": methods[0],  # Primary method
                    "methods": methods,
                    "handler": handler,
                    "file": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "framework": "flask",
                })

        return routes

    def _parse_fastapi_routes(self) -> list[dict]:
        """Parse FastAPI route decorators.

        Returns:
            list of route dicts with path, method, handler, file, line, framework.
        """
        routes = []

        # Pattern for FastAPI route decorators
        # Matches: @app.get('/path'), @app.post('/path'), @router.get('/path'), etc.
        route_pattern = re.compile(
            r"@\w+\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)['\"]"  # Method and path
            r"[^)]*\)\s*\n"                                                              # End of decorator
            r"\s*(?:async\s+)?def\s+(\w+)",                                              # Function name
            re.MULTILINE | re.DOTALL | re.IGNORECASE
        )

        for file_path in self._get_all_files():
            if file_path.suffix != ".py":
                continue

            content = self._read_file_safe(file_path)
            if not content or "@" not in content:
                continue

            for match in route_pattern.finditer(content):
                method = match.group(1).upper()
                path = match.group(2)
                handler = match.group(3)

                # Find line number
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1

                routes.append({
                    "path": path,
                    "method": method,
                    "methods": [method],
                    "handler": handler,
                    "file": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "framework": "fastapi",
                })

        return routes

    def _parse_express_routes(self) -> list[dict]:
        """Parse Express.js routes.

        Returns:
            list of route dicts with path, method, handler, file, line, framework.
        """
        routes = []

        # Pattern for Express routes
        # Matches: app.get('/path', handler), router.post('/path', handler)
        route_pattern = re.compile(
            r"(?:app|router)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        )

        for file_path in self._get_all_files():
            if file_path.suffix not in [".js", ".ts"]:
                continue

            content = self._read_file_safe(file_path)
            if not content:
                continue

            for match in route_pattern.finditer(content):
                method = match.group(1).upper()
                path = match.group(2)

                # Find line number
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1

                routes.append({
                    "path": path,
                    "method": method,
                    "methods": [method],
                    "handler": "anonymous",  # Express often uses inline handlers
                    "file": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "framework": "express",
                })

        return routes

    def _parse_django_routes(self) -> list[dict]:
        """Parse Django URL patterns.

        Returns:
            list of route dicts with path, method, handler, file, line, framework.
        """
        routes = []

        # Pattern for Django URL patterns
        # Matches: path('route/', view_name), path('route/', views.handler)
        url_pattern = re.compile(
            r"path\(\s*['\"]([^'\"]*)['\"]"  # Path
            r"\s*,\s*"                        # Comma separator
            r"([\w.]+)",                      # View/handler name
            re.MULTILINE
        )

        for file_path in self._get_all_files():
            if file_path.suffix != ".py":
                continue
            if "urls" not in file_path.name and "routes" not in file_path.name:
                continue

            content = self._read_file_safe(file_path)
            if not content or "path(" not in content:
                continue

            for match in url_pattern.finditer(content):
                path = "/" + match.group(1) if not match.group(1).startswith("/") else match.group(1)
                handler = match.group(2)

                # Find line number
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1

                routes.append({
                    "path": path,
                    "method": "ALL",  # Django views handle method routing internally
                    "methods": ["GET", "POST", "PUT", "DELETE"],
                    "handler": handler,
                    "file": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "framework": "django",
                })

        return routes
