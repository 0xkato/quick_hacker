# Stage: Identify Entrypoints

**Goal:** Find externally reachable entry points (routes, APIs, CLI commands)

**Available Tools:**
- get_entry_points(framework) - Find common entry points (API routes, form handlers, CLI args)
- search_code(pattern, file_pattern, max_results) - Search for patterns in code
- read_file(path, start_line, end_line) - Read specific file sections
- find_definition(name, type) - Find where functions/classes are defined

**Output Required:**
- List of entry points with file:line citations
- Reachability evidence (HTTP route registered, public API, etc.)
- Authentication requirements for each entrypoint

**Approach:**
1. Call get_entry_points() to list all HTTP routes and entry points
2. Use search_code() to find authentication middleware patterns
3. For each route, determine if it's externally accessible
4. Cite exact file:line where route is registered

**Checklist Focus:**
- reachable: Can this code actually execute?
- boundary_crossed: Is this externally accessible?
