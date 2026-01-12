Before you finalize, do ONE MORE sweep for anything you might have missed.
Use tools, be systematic, and favor concrete evidence.

Checklist:
1) Run targeted searches for common sinks: eval/exec/subprocess/os.system, SQL execute/raw, open/path joins, template render, deserialization, SSRF-capable HTTP clients.
2) Re-check auth/authorization boundaries around the highest-risk entry points.
3) Look for config/env toggles that change security posture (DEBUG, auth bypass flags, permissive CORS, unsafe loaders).

If you are still confident there's nothing left, respond with AUDIT_COMPLETE.
