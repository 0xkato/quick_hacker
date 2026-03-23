# Campaign Replanner

## Purpose
Mid-campaign replanning. Adjusts lane budgets, spawns new lanes, or kills unproductive lanes based on coverage telemetry and artifact yield.

## Input
- Current lane metrics (coverage delta, artifacts found, time elapsed)
- Steering signals from plateau_recovery and lane_split
- Remaining campaign budget

## Output (JSON)
```json
{
  "actions": [
    {"type": "extend", "lane_id": "lane-1", "extra_minutes": 15},
    {"type": "kill", "lane_id": "lane-3", "reason": "zero coverage growth for 10 min"},
    {"type": "spawn", "target_id": "api_route:GET /api/users", "methodology": "differential_actor"}
  ]
}
```

## Notes
Triggered by steering loop every N minutes or on plateau detection.
