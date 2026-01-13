# Stage: Trace Dataflow

**Goal:** Follow data flow from source (user input) to sink (dangerous operation)

**Available Tools:**
- read_file(path, start_line, end_line) - Read specific file sections
- trace_data_flow(source, file_path, sink_patterns) - Trace how data flows from source to sinks
- find_usages(name, max_results) - Find all places where a function/variable is used
- search_code(pattern, file_pattern, max_results) - Search for patterns in code

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
