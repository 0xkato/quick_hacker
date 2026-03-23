# Plateau Recovery Steering

## Purpose
Detect and recover from coverage plateaus. When a lane stops discovering new coverage, suggest mutations to the harness, corpus, or methodology.

## Trigger
- Coverage delta drops below threshold for N consecutive minutes
- Artifact discovery rate drops to zero

## Actions
- Suggest dictionary expansion with new tokens
- Recommend switching from generation to mutation (or vice versa)
- Propose targeted seed inputs for uncovered branches
- Escalate to campaign_replanner if recovery fails

## Notes
First line of defense against wasted compute. Most plateaus resolve with dictionary or seed additions.
