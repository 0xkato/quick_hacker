# Target Prioritizer

## Purpose
Score and rank extracted targets by expected vulnerability yield. Considers attack surface complexity, input validation presence, and historical bug density.

## Input
- Extracted targets from all surface extractors
- Repository metadata (language, framework, age)
- Optional: prior scan results for the same repo

## Output (JSON)
```json
{
  "ranked_targets": [
    {"target_id": "api_route:POST /api/orders", "priority_score": 0.92, "rationale": "No input validation, stateful, handles payments"}
  ]
}
```

## Notes
Runs once at campaign start; campaign_replanner adjusts priorities mid-flight.
