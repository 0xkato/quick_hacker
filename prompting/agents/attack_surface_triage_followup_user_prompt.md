You requested additional context for some items. Make a FINAL decision.

Threat model: {{threat_model}}

Return ONLY JSON with this schema:
{
  "items": [
    {
      "candidate_id": string,
      "verdict": "investigate" | "drop",
      "confidence_score": number (0.0-1.0),
      "exposure": "A" | "B" | "C" | "unknown",
      "reasoning": string
    }
  ]
}

Candidates (JSON array):
{{candidates_json}}
