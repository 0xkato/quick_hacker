# Stage: Trace Dataflow

**Goal:** Follow data flow from source (user input) to sink (dangerous operation)

**Available Tools:**
- ReadFileTool(file_path, line_start, line_end) - Read specific file sections
- CallGraphTool(function_name, max_depth) - Trace function calls
- RipgrepTool(pattern, file_pattern, case_sensitive) - Search for patterns

**Output Required:**
- Step-by-step data flow with file:line citations for each step
- Identification of sanitization/validation attempts
- Evidence that data flows unsanitized to sink

**Approach:**
1. Start from source (e.g., request.args.get('id'))
2. Trace through each assignment, function call, transformation
3. Note any sanitization functions encountered
4. Follow to sink (e.g., cursor.execute())
5. Cite every intermediate step with file:line

**Checklist Focus:**
- source_controlled_input: Is input from user/attacker?
- dataflow_evidenced: Can we trace source → sink?
- Distinguish parameterized queries (safe) from string concatenation (unsafe)
