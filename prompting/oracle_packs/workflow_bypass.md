# Workflow Bypass Oracle

## Purpose
Detect workflow and business logic bypasses by verifying state machine invariants are maintained across request sequences.

## Detection Logic
- Define expected state transitions from state_model extractor
- Flag: state transitions that skip required intermediate states
- Flag: actions succeed in states where they should be forbidden
- Flag: state reverts to previous value without proper authorization

## Pairs With
- stateful_sequence methodology (multi-step sequences)
- differential_actor methodology (cross-actor state manipulation)

## Notes
Requires state_model extractor output to define invariants. High-value oracle for business-critical workflows.
