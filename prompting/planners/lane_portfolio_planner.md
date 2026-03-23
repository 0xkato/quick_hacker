# Lane Portfolio Planner

## Purpose
Allocate fuzz lanes across targets. Selects methodology pack, oracle pack, and time budget for each lane to maximize coverage diversity.

## Input
- Ranked targets from target_prioritizer
- Available methodology packs and oracle packs
- Campaign budget (max lanes, max runtime)

## Output (JSON)
```json
{
  "lanes": [
    {
      "target_id": "api_route:POST /api/orders",
      "methodology": "schema_property",
      "oracle": "authz_diff",
      "budget_minutes": 30
    }
  ]
}
```

## Notes
Portfolio theory: diversify across methodologies to avoid correlation in missed bugs.
