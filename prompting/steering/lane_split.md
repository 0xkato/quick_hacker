# Lane Split Steering

## Purpose
Split a productive lane into multiple specialized lanes when a single lane is covering too many targets or finding diverse bug classes.

## Trigger
- Single lane finding bugs in multiple distinct code regions
- Coverage spread across unrelated modules
- High artifact count with diverse root causes

## Actions
- Clone lane configuration with narrowed target scope
- Split corpus by coverage region
- Assign different oracle packs to each child lane

## Notes
Improves signal quality by isolating bug classes. Campaign_replanner handles budget allocation for child lanes.
