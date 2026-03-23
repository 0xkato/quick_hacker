# SSRF Oracle

## Purpose
Detect server-side request forgery by monitoring for outbound requests to attacker-controlled or internal destinations.

## Detection Logic
- Inject callback URLs (Burp Collaborator-style) in URL-type parameters
- Flag: DNS or HTTP callback received from target server
- Flag: response contains content from internal services (metadata endpoints, localhost)

## Pairs With
- schema_property methodology (mutate URL-typed fields)
- directed methodology (target URL-fetching sinks)

## Notes
Requires callback infrastructure or DNS canary setup. Cloud metadata detection (169.254.169.254) is a high-confidence signal.
