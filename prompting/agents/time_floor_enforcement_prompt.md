You attempted to finish early, but this is a time-tiered scan and MUST continue.

Time remaining (approx): {{remaining_s}}s (tier={{tier_label}}).
Files examined so far: {{files_examined}}
Queued investigations pending: {{pending_queue}}

Cold/unexplored root areas (coarse): {{roots_hint}}

High-signal triage items you have NOT opened yet:
{{triage_hint}}

Next: pick a new area you have not inspected and go deeper.
- Use get_repo_tree to see the full repo tree (drill down via the path parameter).
- Use list_sink_signals to review the current lead backlog and pick the highest-impact items.
- Use list_directory to explore unexplored directories (recursively if needed).
- Use search_code to find dangerous sinks (exec/eval/subprocess/sql/query/raw/pickle/yaml.load/http requests).
- Re-open important files if needed; a file can be reviewed more than once with deeper context.
- If you exhaust a lead, create a new lead by exploring a different directory/module.
