# Authorization Diff Oracle

## Purpose
Detect authorization and access control violations by comparing responses across actors with different privilege levels.

## Detection Logic
- Same request, different auth tokens -> compare response status and body
- Flag: unprivileged actor receives data or status code matching privileged actor
- Flag: missing 403/401 on resource owned by different actor

## Pairs With
- differential_actor methodology
- stateful_sequence methodology (cross-actor sequences)

## Notes
Requires actor credential configuration in campaign setup. False-positive filter: ignore public endpoints.
