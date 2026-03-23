# State Model Extractor

## Purpose
Infer application state machines: user roles, object lifecycles, workflow transitions, and session states. Used by stateful_sequence methodology.

## Input
- Database models / ORM definitions
- Enum and status field definitions
- Route middleware and guard logic

## Output (JSON)
```json
{
  "state_machines": [
    {
      "entity": "Order",
      "states": ["draft", "submitted", "approved", "shipped"],
      "transitions": [
        {"from": "draft", "to": "submitted", "action": "POST /api/orders/:id/submit", "requires_role": "user"}
      ]
    }
  ]
}
```

## Notes
State models feed into stateful_sequence and differential_actor methodology packs.
