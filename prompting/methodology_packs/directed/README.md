# Directed Methodology Pack

## Purpose
Directed fuzzing toward specific code locations (sinks, branches, error handlers). Uses static analysis to identify targets, then steers input generation toward them.

## When to Use
- Known dangerous sinks identified by static analysis
- Specific code paths that are hard to reach with random generation
- Sink-directed shift steering signal triggers this methodology

## Harness Strategy
- Identify target basic blocks from sink_hunter analysis
- Use distance-guided feedback (how close did this input get to the target?)
- Prioritize inputs that reduce distance to target sink

## Notes
Most effective when combined with dataflow analysis. sink_directed_shift steering signal spawns directed lanes.
