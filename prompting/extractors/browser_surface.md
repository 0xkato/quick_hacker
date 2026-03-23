# Browser Surface Extractor

## Purpose
Identify browser-facing attack surfaces: DOM sinks, postMessage handlers, URL fragment consumers, cookie usage, and client-side template rendering.

## Input
- Frontend source files (JS/TS/HTML)
- Framework component definitions
- CSP headers and meta tags

## Output (JSON)
```json
{
  "targets": [
    {
      "kind": "dom_sink",
      "entrypoint": "innerHTML assignment in UserProfile.tsx:42",
      "sink_type": "innerHTML",
      "source": "URL query parameter",
      "language": "typescript"
    }
  ]
}
```

## Notes
Pairs with XSS, clickjacking, and CSP oracle packs. v1 focuses on React/Vue/Angular patterns.
