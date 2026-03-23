# Path Traversal Oracle

## Purpose
Detect path traversal vulnerabilities by monitoring for out-of-bound file access in responses and server-side behavior.

## Detection Logic
- Inject traversal payloads (../, ..%2f, ..%252f) in path and query parameters
- Flag: response contains contents of known sentinel files (/etc/passwd, win.ini)
- Flag: response size/timing anomaly indicating file read success

## Pairs With
- schema_property methodology (mutate path-type fields)
- raw_mutation methodology (byte-level path manipulation)

## Notes
Combine with file-system monitoring when running against local targets for higher confidence.
