# API Surface Extractor

## Purpose
Extract fuzzable API surfaces from a repository. Identifies HTTP routes, REST endpoints, GraphQL resolvers, and WebSocket handlers.

## Input
- Repository file tree
- OpenAPI/Swagger specs (if available)
- Framework-specific route definitions

## Output (JSON)
```json
{
  "targets": [
    {
      "kind": "api_route",
      "entrypoint": "POST /api/orders",
      "language": "python",
      "schemas": ["openapi:/api/orders"],
      "stateful": true
    }
  ]
}
```

## Notes
v1: Deterministic extraction from OpenAPI specs. LM-assisted extraction for repos without specs is v2.
