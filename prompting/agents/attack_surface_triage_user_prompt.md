Decide which items warrant deeper investigation.

Threat model: {{threat_model}}

Return ONLY JSON with this schema:
{
  "items": [
    {
      "candidate_id": string,
      "verdict": "investigate" | "drop" | "needs_context",
      "confidence_score": number (0.0-1.0),
      "exposure": "A" | "B" | "C" | "unknown",
      "reasoning": string,
      "context_request": {
        "path": string,
        "start_line": number,
        "end_line": number,
        "reason": string
      } | null
    }
  ]
}

Rules:
- Be skeptical; it is OK if everything is dropped.
- Only use evidence in metadata/code_context.
- You may set verdict='needs_context' for AT MOST 2 items total.
- If verdict!='needs_context', set context_request=null.

Candidates (JSON array):
{{candidates_json}}
