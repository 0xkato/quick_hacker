"""Prompt enrichment stage - adds context and expands scope."""

from typing import Optional, Tuple

from models.schemas import ProviderConfig, ProviderType
from providers import get_provider
from providers.base_provider import Message


ENRICHMENT_SYSTEM_PROMPT = """You are a security analysis prompt enrichment specialist.

Your job is to take a user's security analysis request and ENRICH it by:
1. Adding relevant security context the user may have missed
2. Expanding scope to related vulnerability classes
3. Suggesting specific attack vectors to check
4. Adding language/framework-specific concerns

RULES:
- Keep the original intent intact
- Add specific OWASP categories to check
- Mention CWE IDs where relevant
- Include framework-specific vulnerabilities if you can identify the stack
- Be concise - don't add unnecessary verbosity

Output ONLY the enriched prompt, nothing else."""


class PromptEnricher:
    """Enriches security analysis prompts with additional context."""

    async def enrich(
        self,
        prompt: str,
        code_context: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        provider_config: Optional[ProviderConfig] = None,
    ) -> Tuple[str, int, int]:
        """
        Enrich a security analysis prompt with additional context.

        Args:
            prompt: Original user prompt
            code_context: Code snippet being analyzed
            file_path: Path to the file (for context)
            language: Programming language

        Returns:
            Tuple of (enriched_prompt, tokens_in, tokens_out)
        """
        if provider_config is None:
            provider_config = ProviderConfig(
                provider=ProviderType.OPENAI,
                model="gpt-4o-mini",
                temperature=0.0,
                max_tokens=2000,
            )

        provider = get_provider(provider_config)

        # Build context message
        context_parts = [f"Original prompt: {prompt}"]

        if file_path:
            context_parts.append(f"File: {file_path}")

        if language:
            context_parts.append(f"Language: {language}")

        # Include a sample of the code for context (first 500 chars)
        code_sample = code_context[:500] + "..." if len(code_context) > 500 else code_context
        context_parts.append(f"Code sample:\n```\n{code_sample}\n```")

        user_message = "\n\n".join(context_parts)

        messages = [Message(role="user", content=user_message)]

        # Generate enriched prompt
        enriched = await provider.generate(messages, ENRICHMENT_SYSTEM_PROMPT)

        # Estimate tokens
        tokens_in = len(user_message) // 4 + len(ENRICHMENT_SYSTEM_PROMPT) // 4
        tokens_out = len(enriched) // 4

        return enriched.strip(), tokens_in, tokens_out

    def _detect_language(self, file_path: Optional[str], code: str) -> Optional[str]:
        """Attempt to detect the programming language."""
        if file_path:
            ext_map = {
                ".py": "Python",
                ".js": "JavaScript",
                ".ts": "TypeScript",
                ".java": "Java",
                ".go": "Go",
                ".rs": "Rust",
                ".php": "PHP",
                ".rb": "Ruby",
                ".c": "C",
                ".cpp": "C++",
                ".cs": "C#",
                ".sol": "Solidity",
            }
            for ext, lang in ext_map.items():
                if file_path.endswith(ext):
                    return lang

        # Fallback: simple heuristics
        if "def " in code and "import " in code:
            return "Python"
        if "function " in code or "const " in code or "let " in code:
            return "JavaScript"
        if "public class " in code:
            return "Java"

        return None
