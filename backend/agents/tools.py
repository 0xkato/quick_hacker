"""
Tools available to the security research agent.

These tools allow the agent to explore and analyze a codebase
just like a human security researcher would.
"""

import os
import re
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass


@dataclass
class ToolResult:
    """Result from executing a tool."""
    success: bool
    data: Any
    error: Optional[str] = None


# Tool definitions for LLM (OpenAI/Anthropic format)
AGENT_TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file. Use this to examine source code, configs, or any file in the repository.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to repository root (e.g., 'src/auth/login.py')"
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional: Start reading from this line number (1-indexed)"
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional: Stop reading at this line number"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "search_code",
        "description": "Search for a regex pattern across the codebase. Returns matching lines with file paths and line numbers. Use this to find function definitions, variable usage, import statements, etc.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (e.g., 'def authenticate', 'os\\.system', 'eval\\s*\\(')"
                },
                "file_pattern": {
                    "type": "string",
                    "description": "Optional: Glob pattern to filter files (e.g., '*.py', '*.js', 'src/**/*.ts')"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 50)"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_directory",
        "description": "List files and directories in a path. Use this to explore the repository structure.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path relative to repository root (use '.' for root)"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "If true, list all files recursively (default: false)"
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional: Filter files by glob pattern (e.g., '*.py')"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "find_definition",
        "description": "Find where a function, class, or variable is defined. Useful for tracing code flow.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the function, class, or variable to find"
                },
                "type": {
                    "type": "string",
                    "enum": ["function", "class", "variable", "any"],
                    "description": "Type of definition to search for (default: 'any')"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "find_usages",
        "description": "Find all places where a function, class, or variable is used/called. Essential for tracing data flow.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the function, class, or variable"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 30)"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "get_file_structure",
        "description": "Get an overview of a file's structure - classes, functions, imports. Useful for understanding a file before diving into details.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to repository root"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "trace_data_flow",
        "description": "Trace how data flows from a source to potential sinks. Provide a variable or function that handles user input.",
        "parameters": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "The source variable/function to trace (e.g., 'request.form', 'user_input')"
                },
                "file_path": {
                    "type": "string",
                    "description": "File where the source is located"
                },
                "sink_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional: Patterns of dangerous sinks to look for (e.g., ['execute', 'eval', 'system'])"
                }
            },
            "required": ["source", "file_path"]
        }
    },
    {
        "name": "report_finding",
        "description": "Report a CONFIRMED security vulnerability. Only use this when you have verified the vulnerability exists with concrete evidence. False positives waste time.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity based on exploitability and impact"
                },
                "title": {
                    "type": "string",
                    "description": "Clear, concise title (e.g., 'SQL Injection in user search')"
                },
                "vulnerability_type": {
                    "type": "string",
                    "description": "Type of vulnerability (e.g., 'SQL Injection', 'Command Injection', 'XSS')"
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., 'CWE-89' for SQL injection)"
                },
                "file_path": {
                    "type": "string",
                    "description": "Path to the vulnerable file"
                },
                "line_start": {
                    "type": "integer",
                    "description": "Starting line number of vulnerable code"
                },
                "line_end": {
                    "type": "integer",
                    "description": "Ending line number (optional)"
                },
                "vulnerable_code": {
                    "type": "string",
                    "description": "The exact vulnerable code snippet"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed explanation of the vulnerability"
                },
                "source_trace": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Step-by-step trace from user input to sink"
                },
                "attack_scenario": {
                    "type": "string",
                    "description": "How an attacker would exploit this"
                },
                "proof_of_concept": {
                    "type": "string",
                    "description": "Example payload or exploit code"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "Confidence level (0.0-1.0). Only report if >= 0.8"
                },
                "recommended_fix": {
                    "type": "string",
                    "description": "How to fix this vulnerability"
                }
            },
            "required": ["severity", "title", "vulnerability_type", "file_path", "line_start", "vulnerable_code", "description", "confidence"]
        }
    },
    {
        "name": "add_investigation_note",
        "description": "Add a note to your investigation log. Use this to track your analysis, hypotheses, and things to check.",
        "parameters": {
            "type": "object",
            "properties": {
                "note": {
                    "type": "string",
                    "description": "Your investigation note"
                },
                "category": {
                    "type": "string",
                    "enum": ["hypothesis", "confirmed", "ruled_out", "todo", "observation"],
                    "description": "Category of the note"
                }
            },
            "required": ["note", "category"]
        }
    },
    {
        "name": "get_entry_points",
        "description": "Find common entry points in the application - API routes, form handlers, CLI args, etc. Good starting point for finding attack surface.",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Optional: Framework to look for (e.g., 'flask', 'django', 'express', 'fastapi')"
                }
            }
        }
    }
]


# Build tool definition lookup for validation
TOOL_DEFINITIONS = {tool["name"]: tool for tool in AGENT_TOOLS}


class ToolExecutor:
    """Executes tools for the security research agent."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.investigation_notes: list[dict] = []

    def _safe_path(self, path: str) -> Path:
        """Ensure path doesn't escape repository."""
        full_path = (self.repo_path / path).resolve()
        repo_root = self.repo_path.resolve()
        try:
            full_path.relative_to(repo_root)
        except ValueError:
            raise ValueError(f"Path escapes repository: {path}")
        return full_path

    async def execute(self, tool_name: str, arguments: dict) -> ToolResult:
        """Execute a tool and return the result."""
        try:
            method = getattr(self, f"_tool_{tool_name}", None)
            if not method:
                return ToolResult(False, None, f"Unknown tool: {tool_name}")

            # Validate required arguments
            tool_def = TOOL_DEFINITIONS.get(tool_name)
            if tool_def:
                required = tool_def.get("parameters", {}).get("required", [])
                missing = [arg for arg in required if arg not in arguments]
                if missing:
                    return ToolResult(
                        False, None,
                        f"Missing required argument(s): {', '.join(missing)}. "
                        f"Tool {tool_name} requires: {', '.join(required)}"
                    )

            return await method(**arguments)
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> ToolResult:
        """Read file contents."""
        try:
            file_path = self._safe_path(path)
            if not file_path.exists():
                return ToolResult(False, None, f"File not found: {path}")

            if not file_path.is_file():
                return ToolResult(False, None, f"Not a file: {path}")

            # Check file size
            if file_path.stat().st_size > 1_000_000:  # 1MB limit
                return ToolResult(False, None, "File too large (>1MB)")

            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')

            if start_line or end_line:
                start_idx = (start_line - 1) if start_line else 0
                end_idx = end_line if end_line else len(lines)
                lines = lines[start_idx:end_idx]
                # Add line numbers
                numbered = [f"{i + start_idx + 1}: {line}" for i, line in enumerate(lines)]
                return ToolResult(True, '\n'.join(numbered))

            # Add line numbers
            numbered = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
            return ToolResult(True, '\n'.join(numbered))

        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_search_code(
        self,
        pattern: str,
        file_pattern: Optional[str] = None,
        max_results: int = 50
    ) -> ToolResult:
        """Search for pattern in codebase."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return ToolResult(False, None, f"Invalid regex: {e}")

        results = []
        files_searched = 0

        for root, dirs, files in os.walk(self.repo_path):
            # Skip hidden and common non-source dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in [
                'node_modules', '__pycache__', 'venv', '.git', 'dist', 'build'
            ]]

            for filename in files:
                if file_pattern and not Path(filename).match(file_pattern.replace('**/', '')):
                    continue

                file_path = Path(root) / filename
                rel_path = file_path.relative_to(self.repo_path)

                # Skip binary files
                if file_path.suffix in ['.png', '.jpg', '.gif', '.ico', '.woff', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz']:
                    continue

                try:
                    content = file_path.read_text(errors='ignore')
                    files_searched += 1

                    for i, line in enumerate(content.split('\n'), 1):
                        if regex.search(line):
                            results.append({
                                'file': str(rel_path),
                                'line': i,
                                'content': line.strip()[:200]
                            })
                            if len(results) >= max_results:
                                break

                    if len(results) >= max_results:
                        break
                except:
                    continue

            if len(results) >= max_results:
                break

        return ToolResult(True, {
            'matches': results,
            'count': len(results),
            'files_searched': files_searched,
            'truncated': len(results) >= max_results
        })

    async def _tool_list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        pattern: Optional[str] = None
    ) -> ToolResult:
        """List directory contents."""
        try:
            dir_path = self._safe_path(path)
            if not dir_path.exists():
                return ToolResult(False, None, f"Directory not found: {path}")

            if not dir_path.is_dir():
                return ToolResult(False, None, f"Not a directory: {path}")

            items = []

            if recursive:
                for root, dirs, files in os.walk(dir_path):
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in [
                        'node_modules', '__pycache__', 'venv', '.git'
                    ]]
                    for f in files:
                        if pattern and not Path(f).match(pattern):
                            continue
                        rel = (Path(root) / f).relative_to(self.repo_path)
                        items.append(str(rel))
                    if len(items) > 500:
                        break
            else:
                for item in sorted(dir_path.iterdir()):
                    if item.name.startswith('.'):
                        continue
                    if pattern and not item.match(pattern):
                        continue
                    rel = item.relative_to(self.repo_path)
                    suffix = '/' if item.is_dir() else ''
                    items.append(f"{rel}{suffix}")

            return ToolResult(True, {
                'path': path,
                'items': items[:500],
                'count': len(items),
                'truncated': len(items) > 500
            })

        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_find_definition(
        self,
        name: str,
        type: str = "any"
    ) -> ToolResult:
        """Find where something is defined."""
        patterns = {
            'function': [
                rf'def\s+{re.escape(name)}\s*\(',  # Python
                rf'function\s+{re.escape(name)}\s*\(',  # JS
                rf'const\s+{re.escape(name)}\s*=\s*(?:async\s*)?\(',  # Arrow function
                rf'func\s+{re.escape(name)}\s*\(',  # Go
                rf'fn\s+{re.escape(name)}\s*\(',  # Rust
            ],
            'class': [
                rf'class\s+{re.escape(name)}[\s:(]',  # Python/JS
                rf'type\s+{re.escape(name)}\s+struct',  # Go
                rf'struct\s+{re.escape(name)}\s*{{',  # Rust
            ],
            'variable': [
                rf'{re.escape(name)}\s*=',
                rf'const\s+{re.escape(name)}\s*=',
                rf'let\s+{re.escape(name)}\s*=',
                rf'var\s+{re.escape(name)}\s*=',
            ]
        }

        if type == 'any':
            search_patterns = patterns['function'] + patterns['class'] + patterns['variable']
        else:
            search_patterns = patterns.get(type, [])

        combined_pattern = '|'.join(f'({p})' for p in search_patterns)
        return await self._tool_search_code(combined_pattern, max_results=20)

    async def _tool_find_usages(
        self,
        name: str,
        max_results: int = 30
    ) -> ToolResult:
        """Find all usages of a name."""
        # Match the name as a word (not part of another word)
        pattern = rf'\b{re.escape(name)}\b'
        return await self._tool_search_code(pattern, max_results=max_results)

    async def _tool_get_file_structure(self, path: str) -> ToolResult:
        """Get overview of file structure."""
        try:
            file_path = self._safe_path(path)
            if not file_path.exists():
                return ToolResult(False, None, f"File not found: {path}")

            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')

            structure = {
                'imports': [],
                'classes': [],
                'functions': [],
                'routes': [],
                'line_count': len(lines)
            }

            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                # Imports
                if stripped.startswith(('import ', 'from ')) or 'require(' in stripped:
                    structure['imports'].append({'line': i, 'content': stripped[:100]})

                # Classes
                if re.match(r'^class\s+\w+', stripped):
                    match = re.match(r'class\s+(\w+)', stripped)
                    if match:
                        structure['classes'].append({'line': i, 'name': match.group(1)})

                # Functions
                if re.match(r'^(async\s+)?def\s+\w+', stripped) or re.match(r'^(async\s+)?function\s+\w+', stripped):
                    match = re.search(r'(?:def|function)\s+(\w+)', stripped)
                    if match:
                        structure['functions'].append({'line': i, 'name': match.group(1)})

                # Routes/endpoints
                if re.search(r'@(app|router|blueprint)\.(get|post|put|delete|patch|route)', stripped, re.IGNORECASE):
                    structure['routes'].append({'line': i, 'content': stripped[:100]})
                if re.search(r'\.(get|post|put|delete|patch)\s*\([\'"]', stripped, re.IGNORECASE):
                    structure['routes'].append({'line': i, 'content': stripped[:100]})

            return ToolResult(True, structure)

        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_trace_data_flow(
        self,
        source: str,
        file_path: str,
        sink_patterns: Optional[list[str]] = None
    ) -> ToolResult:
        """Trace data flow from source to sinks."""
        default_sinks = [
            'execute', 'exec', 'eval', 'system', 'popen', 'subprocess',
            'query', 'raw', 'cursor', 'execute_sql',
            'render', 'innerHTML', 'document.write',
            'open', 'read', 'write', 'readFile', 'writeFile',
            'redirect', 'send', 'sendFile',
            'pickle', 'load', 'loads', 'yaml.load',
            'shell', 'spawn', 'fork'
        ]

        sinks = sink_patterns or default_sinks

        # Read the file
        file_result = await self._tool_read_file(file_path)
        if not file_result.success:
            return file_result

        content = file_result.data
        lines = content.split('\n')

        # Find source usages
        source_lines = []
        sink_lines = []

        source_pattern = re.compile(re.escape(source), re.IGNORECASE)
        sink_pattern = re.compile('|'.join(rf'\b{re.escape(s)}\b' for s in sinks), re.IGNORECASE)

        for line in lines:
            # Extract line number and content
            match = re.match(r'^(\d+):\s*(.*)$', line)
            if not match:
                continue
            line_num = int(match.group(1))
            line_content = match.group(2)

            if source_pattern.search(line_content):
                source_lines.append({'line': line_num, 'content': line_content.strip()[:150]})

            if sink_pattern.search(line_content):
                sink_lines.append({'line': line_num, 'content': line_content.strip()[:150]})

        # Look for potential flows (source and sink in proximity)
        potential_flows = []
        for src in source_lines:
            for sink in sink_lines:
                if abs(src['line'] - sink['line']) < 50:  # Within 50 lines
                    potential_flows.append({
                        'source': src,
                        'sink': sink,
                        'distance': abs(src['line'] - sink['line'])
                    })

        return ToolResult(True, {
            'source': source,
            'file': file_path,
            'source_occurrences': source_lines[:20],
            'sink_occurrences': sink_lines[:20],
            'potential_flows': sorted(potential_flows, key=lambda x: x['distance'])[:10],
            'needs_manual_review': len(potential_flows) > 0
        })

    async def _tool_report_finding(self, **kwargs) -> ToolResult:
        """Report a finding - this is handled specially by the agent."""
        # The agent loop will intercept this and create a proper Finding
        return ToolResult(True, {'reported': True, 'finding': kwargs})

    async def _tool_add_investigation_note(
        self,
        note: str,
        category: str = "observation"
    ) -> ToolResult:
        """Add investigation note."""
        self.investigation_notes.append({
            'note': note,
            'category': category
        })
        return ToolResult(True, f"Note added ({category}): {note[:50]}...")

    async def _tool_get_entry_points(
        self,
        framework: Optional[str] = None
    ) -> ToolResult:
        """Find application entry points."""
        entry_patterns = {
            'flask': [
                r'@app\.route\s*\([\'"]([^\'"]+)',
                r'@blueprint\.route\s*\([\'"]([^\'"]+)',
            ],
            'django': [
                r'path\s*\([\'"]([^\'"]+)',
                r'url\s*\([\'"]([^\'"]+)',
            ],
            'fastapi': [
                r'@app\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
                r'@router\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
            ],
            'express': [
                r'app\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
                r'router\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
            ],
            'generic': [
                r'@(Get|Post|Put|Delete|Patch)Mapping\s*\([\'"]?([^\'")\s]+)',  # Spring
                r'func\s+\w+Handler',  # Go handlers
                r'def\s+(get|post|put|delete|patch)_\w+',  # Common REST patterns
            ]
        }

        patterns_to_use = []
        if framework and framework in entry_patterns:
            patterns_to_use = entry_patterns[framework]
        else:
            for p_list in entry_patterns.values():
                patterns_to_use.extend(p_list)

        all_entries = []
        for pattern in patterns_to_use:
            result = await self._tool_search_code(pattern, max_results=100)
            if result.success and result.data.get('matches'):
                all_entries.extend(result.data['matches'])

        # Also find CLI argument parsing
        cli_result = await self._tool_search_code(
            r'(argparse|argv|getopt|click\.command|typer\.command)',
            max_results=20
        )
        if cli_result.success and cli_result.data.get('matches'):
            all_entries.extend([
                {**m, 'type': 'cli'} for m in cli_result.data['matches']
            ])

        # Find form handlers
        form_result = await self._tool_search_code(
            r'(request\.(form|data|json|args|files)|req\.body|FormData)',
            max_results=50
        )
        if form_result.success and form_result.data.get('matches'):
            all_entries.extend([
                {**m, 'type': 'user_input'} for m in form_result.data['matches']
            ])

        return ToolResult(True, {
            'entry_points': all_entries[:100],
            'count': len(all_entries),
            'truncated': len(all_entries) > 100
        })
