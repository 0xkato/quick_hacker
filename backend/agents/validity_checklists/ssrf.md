# SSRF (Server-Side Request Forgery) Validity Checklist

Use this checklist when evaluating a suspected SSRF vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Attacker Influences Request Destination
- [ ] Attacker-controlled data affects URL/host/scheme/port of outbound request
- [ ] Input flows into HTTP client, URL fetcher, or network connection function
- [ ] Examples: `requests.get()`, `fetch()`, `curl`, `HTTPClient.get()`, `URLConnection`

### 2. No Effective Allowlist or Network-Level Protection
- [ ] No allowlist restricts destinations to safe hosts/schemes OR allowlist is bypassable
- [ ] No blocklist prevents internal IPs OR blocklist is incomplete (missing IPv6, DNS rebinding, redirects)
- [ ] No DNS pinning or network segmentation prevents internal network access
- [ ] URL parsing inconsistencies can bypass validation

### 3. Reachability Plausible
- [ ] Code path is reachable from attacker-controlled entry point
- [ ] Not disabled/admin-only with strong auth
- [ ] Configuration/routing analysis confirms exposure

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Preconfigured Endpoints Only**: Application uses predefined list of endpoints, user only selects from list.
  - Example: `endpoints = {'weather': 'api.weather.com', 'news': 'api.news.com'}; fetch(endpoints[userChoice])`

- **Strongly Allowlisted Components**: All URL components (scheme, host, port, path prefix) validated against strict allowlist.
  - Example: `if (url.startsWith('https://api.example.com/v1/')) { fetch(url) }` with proper URL parsing

- **Isolated Network Context**: Requests execute in isolated environment with no access to internal resources.
  - Example: Serverless functions with VPC restrictions preventing internal network access

- **URL Path/Query Only**: Attacker controls only path/query parameters, not host/scheme.
  - Example: `fetch('https://api.example.com/data?id=' + userId)` where userId affects query but not destination

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where attacker data enters (file path + line number + code snippet)
2. **Exact sink**: Where outbound request is made (file path + line number + code snippet)
3. **Dataflow trace**: How attacker data reaches the sink affecting destination
4. **Mitigation analysis**: Why allowlists/blocklists/network protections are absent, incomplete, or bypassable
5. **Reachability**: Evidence the code path is reachable (routing/auth/config)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, attacker can make requests to arbitrary destinations including internal resources
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about network-level protections, DNS behavior, or redirect handling
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (allowlists, network segmentation) reduce exploitability
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (strong allowlist, preconfigured endpoints, isolated network)
