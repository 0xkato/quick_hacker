# Stage: Identify Entrypoints

**Goal:** Find externally reachable entry points (routes, APIs, CLI commands)

**Available Tools:**
- GetRoutesTool() - Returns all HTTP routes
- GetAuthGatesTool() - Returns authentication middleware
- FindSymbolTool(symbol_name, symbol_type) - Find specific symbols

**Output Required:**
- List of entry points with file:line citations
- Reachability evidence (HTTP route registered, public API, etc.)
- Authentication requirements for each entrypoint

**Approach:**
1. Call GetRoutesTool() to list all HTTP routes
2. Call GetAuthGatesTool() to understand authentication middleware
3. For each route, determine if it's externally accessible
4. Cite exact file:line where route is registered

**Checklist Focus:**
- reachable: Can this code actually execute?
- boundary_crossed: Is this externally accessible?
