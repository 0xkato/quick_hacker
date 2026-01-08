"""Deep scan agent for thorough security analysis."""

import asyncio
from pathlib import Path

from models.schemas import AgentType
from services import file_service
from .base_agent import BaseAgent


class DeepScanAgent(BaseAgent):
    """
    Thorough security analysis agent.

    - Analyzes entire codebase methodically
    - Follows data flow from sources to sinks
    - Cross-file analysis where possible
    - Slower but comprehensive
    """

    agent_type = AgentType.DEEP_SCAN

    # File extensions to analyze (security-relevant)
    ANALYZED_EXTENSIONS = [
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rs", ".c", ".cpp",
        ".rb", ".php", ".cs", ".swift", ".kt",
        ".scala", ".sol",
    ]

    async def analyze(self):
        """Run deep security analysis on the repository."""
        await self.emit_log("Starting deep scan analysis...")

        # Get files to analyze
        if self.target_files:
            files = self.target_files
        else:
            files = await file_service.get_files_by_extension(
                self.repo_path,
                self.ANALYZED_EXTENSIONS,
                max_files=500,
            )

        total_files = len(files)
        await self.emit_log(f"Found {total_files} files to analyze")

        # Analyze each file
        for idx, file_path in enumerate(files):
            if self._cancelled:
                break

            # Check for pause
            while self.status.value == "paused":
                await asyncio.sleep(1)
                if self._cancelled:
                    break

            await self.emit_progress(idx + 1, total_files, file_path)

            try:
                # Read file content
                file_content = await file_service.read_file(self.repo_path, file_path)

                # Skip very small files
                if file_content.line_count < 5:
                    continue

                await self.emit_log(f"Analyzing: {file_path}")

                # Analyze the file
                await self.analyze_file(file_path, file_content.content)

                self.files_analyzed += 1

            except Exception as e:
                await self.emit_log(f"Error analyzing {file_path}: {e}")
                continue

            # Small delay to prevent rate limiting
            await asyncio.sleep(0.5)

        # Final summary
        await self.emit_log(
            f"Deep scan complete. Analyzed {self.files_analyzed} files, "
            f"found {len(self.findings)} potential vulnerabilities."
        )


class DataFlowAgent(DeepScanAgent):
    """
    Enhanced deep scan that tracks data flow.

    Identifies sources (user input, external data) and traces
    them to sinks (database queries, command execution, etc.)
    """

    async def analyze(self):
        """Run data flow analysis."""
        await self.emit_log("Starting data flow analysis...")

        # First pass: identify all sources and sinks
        sources = await self._find_sources()
        sinks = await self._find_sinks()

        await self.emit_log(f"Found {len(sources)} potential data sources")
        await self.emit_log(f"Found {len(sinks)} potential data sinks")

        # Analyze files containing sources and sinks with extra context
        critical_files = set()
        for item in sources + sinks:
            critical_files.add(item["file"])

        await self.emit_log(f"Analyzing {len(critical_files)} critical files...")

        total = len(critical_files)
        for idx, file_path in enumerate(critical_files):
            if self._cancelled:
                break

            await self.emit_progress(idx + 1, total, file_path)

            try:
                file_content = await file_service.read_file(self.repo_path, file_path)

                # Enhanced prompt for data flow
                await self._analyze_with_context(
                    file_path,
                    file_content.content,
                    sources=[s for s in sources if s["file"] == file_path],
                    sinks=[s for s in sinks if s["file"] == file_path],
                )

                self.files_analyzed += 1

            except Exception as e:
                await self.emit_log(f"Error: {e}")

            await asyncio.sleep(0.5)

    async def _find_sources(self) -> list[dict]:
        """Find data sources (user input, external data)."""
        patterns = [
            r"request\.",
            r"req\.(body|query|params)",
            r"input\(",
            r"argv",
            r"getenv",
            r"os\.environ",
            r"\.read\(",
            r"fetch\(",
            r"axios\.",
            r"HttpRequest",
        ]

        sources = []
        for pattern in patterns:
            results = await file_service.search_files(
                self.repo_path,
                pattern,
                max_results=50,
            )
            sources.extend(results)

        return sources

    async def _find_sinks(self) -> list[dict]:
        """Find data sinks (dangerous operations)."""
        patterns = [
            r"execute\(",
            r"exec\(",
            r"eval\(",
            r"subprocess",
            r"os\.system",
            r"\.query\(",
            r"\.raw\(",
            r"innerHTML",
            r"dangerouslySetInnerHTML",
            r"serialize",
            r"pickle",
            r"yaml\.load",
        ]

        sinks = []
        for pattern in patterns:
            results = await file_service.search_files(
                self.repo_path,
                pattern,
                max_results=50,
            )
            sinks.extend(results)

        return sinks

    async def _analyze_with_context(
        self,
        file_path: str,
        content: str,
        sources: list[dict],
        sinks: list[dict],
    ):
        """Analyze file with data flow context."""
        # Add context about identified sources and sinks
        context = "\n\nKNOWN DATA FLOW POINTS:\n"

        if sources:
            context += "\nData Sources (user/external input):\n"
            for s in sources[:5]:
                context += f"  - Line {s['line']}: {s['content'][:100]}\n"

        if sinks:
            context += "\nData Sinks (dangerous operations):\n"
            for s in sinks[:5]:
                context += f"  - Line {s['line']}: {s['content'][:100]}\n"

        # Modify content with context
        enhanced_content = f"{context}\n\n---\nFILE CONTENT:\n{content}"

        await self.analyze_file(file_path, enhanced_content)
