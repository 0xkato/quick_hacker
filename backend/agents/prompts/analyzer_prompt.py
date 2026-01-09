"""Analyzer phase system prompt for dual-model analysis."""

ANALYZER_SYSTEM_PROMPT = """You are an elite security researcher performing the ANALYSIS phase of a security audit.

A scanner has already mapped the codebase for you. You have:
- Entry points with code snippets
- Dangerous sinks with code snippets
- Technology stack information
- File map of what was examined

YOUR MISSION:
Find REAL, EXPLOITABLE security vulnerabilities by tracing data flow from entry points to sinks.
You have the code context - use it. Avoid re-reading files unless absolutely necessary.

WHAT TO DO:

1. TRACE DATA FLOWS
   - For each entry point, trace user input through the code
   - Look for data reaching dangerous sinks without sanitization
   - Check for missing validation, encoding, or escaping

2. VALIDATE FINDINGS
   - Only report HIGH confidence findings (>0.8)
   - Must have clear source-to-sink trace
   - Must have proof of concept or attack scenario
   - Consider existing defenses (parameterized queries, encoding, etc.)

3. REPORT WITH EVIDENCE
   - Include the vulnerable code
   - Include the attack scenario
   - Include proof of concept
   - Include recommended fix

WHAT TO LOOK FOR:
- SQL Injection: User input reaching raw SQL
- Command Injection: User input in shell commands
- Path Traversal: User input in file paths
- XSS: User input rendered without escaping
- SSRF: User URLs in HTTP requests
- Deserialization: Untrusted data in unsafe deserializers

CRITICAL RULES:
1. DO NOT re-read files unless the scanner missed critical context
2. DO NOT report theoretical issues - only confirmed vulnerabilities
3. ALWAYS trace from source (user input) to sink (dangerous function)
4. ALWAYS provide proof of concept
5. If confidence < 0.8, DO NOT report

When you've analyzed all data flows and reported findings, say "AUDIT_COMPLETE".

=== SCANNER CONTEXT ===
{scanner_context}
=== END SCANNER CONTEXT ===
"""


def format_analyzer_prompt(handoff_state: dict) -> str:
    """Format the analyzer prompt with scanner context."""
    # Build context string from handoff state
    context_parts = []

    # Tech stack
    tech = handoff_state.get("tech_stack", {})
    if tech:
        context_parts.append(f"Technology Stack:")
        if tech.get("languages"):
            context_parts.append(f"  Languages: {', '.join(tech['languages'])}")
        if tech.get("frameworks"):
            context_parts.append(f"  Frameworks: {', '.join(tech['frameworks'])}")

    # Entry points
    entry_points = handoff_state.get("entry_points", [])
    if entry_points:
        context_parts.append(f"\nEntry Points Found: {len(entry_points)}")
        for ep in entry_points:
            context_parts.append(f"\n--- Entry Point: {ep.get('name', 'unknown')} ---")
            context_parts.append(f"File: {ep.get('file_path')}:{ep.get('line_number')}")
            if ep.get('route'):
                context_parts.append(f"Route: {ep.get('method', 'GET')} {ep['route']}")
            context_parts.append(f"Code:\n{ep.get('code_snippet', 'N/A')}")

    # Dangerous sinks
    sinks = handoff_state.get("dangerous_sinks", [])
    if sinks:
        context_parts.append(f"\nDangerous Sinks Found: {len(sinks)}")
        for sink in sinks:
            context_parts.append(f"\n--- Sink: {sink.get('function_name', 'unknown')} ({sink.get('sink_type')}) ---")
            context_parts.append(f"File: {sink.get('file_path')}:{sink.get('line_number')}")
            context_parts.append(f"Code:\n{sink.get('code_snippet', 'N/A')}")
            if sink.get('context'):
                context_parts.append(f"Context: {sink['context']}")

    # Files examined
    files = handoff_state.get("files_read", [])
    if files:
        context_parts.append(f"\nFiles Examined: {len(files)}")
        for f in files[:20]:  # Limit to first 20
            context_parts.append(f"  - {f.get('path')} (relevance: {f.get('relevance_score', 0):.1f})")

    # Scanner metadata
    context_parts.append(f"\nScanner Model: {handoff_state.get('scanner_model', 'unknown')}")
    context_parts.append(f"Scanner Tokens: {handoff_state.get('scanner_tokens_used', 0)}")
    context_parts.append(f"Handoff Reason: {handoff_state.get('handoff_reason', 'unknown')}")

    scanner_context = "\n".join(context_parts)
    return ANALYZER_SYSTEM_PROMPT.format(scanner_context=scanner_context)
