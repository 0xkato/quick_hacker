"""Analyzer phase system prompt for dual-model analysis."""

from prompting_loader import render_prompt


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
    return render_prompt("agents/analyzer_system_prompt.md", scanner_context=scanner_context)
