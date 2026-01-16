"""
Input channel inference logic.

Infers input channel from evidence using 2-signal minimum.
Keeps EvidenceGatherer from becoming a monolith of regexes.

Conservative: defaults to unknown unless 2-signal threshold is met.
"""

import re
from models.schemas import Finding, Evidence, InputChannel


def infer_input_channel(*, finding: Finding, evidence: Evidence) -> None:
    """
    Infer input channel from evidence (mutates evidence in-place).

    Conservative: default unknown unless 2-signal threshold met.

    Args:
        finding: Finding being analyzed
        evidence: Evidence bundle (mutated in-place)
    """
    # Default
    evidence.input_channel = InputChannel.unknown
    evidence.input_channel_deterministic = False
    evidence.input_channel_signals = []
    evidence.input_channel_reason = ""

    # Helper to set deterministic channel
    def set_deterministic(ch: InputChannel, signals: list[str], reason: str):
        evidence.input_channel = ch
        evidence.input_channel_deterministic = True
        evidence.input_channel_signals = signals
        evidence.input_channel_reason = reason

    # Precedence order (prevents overlaps)

    # 1) WebSocket network
    signals = _collect_websocket_signals(evidence)
    if {"websocket_registration", "websocket_message_read"} <= set(signals):
        return set_deterministic(
            InputChannel.network,
            signals,
            "ws registration + message read"
        )

    # 2) HTTP network
    signals = _collect_http_signals(evidence)
    if "route_registration" in signals and (
        "request_data_read" in signals or "framework_param_binding" in signals
    ):
        return set_deterministic(
            InputChannel.network,
            signals,
            "route + request/binding"
        )

    # 3) File input
    signals = _collect_file_signals(evidence)
    if "file_upload_api" in signals and (
        "external_file_read" in signals or "file_parse_operation" in signals
    ):
        return set_deterministic(
            InputChannel.file_input,
            signals,
            "upload + read/parse"
        )

    # 4) Web content
    signals = _collect_web_signals(evidence)
    if "dom_sink_use" in signals and (
        "browser_source_read" in signals or "message_event_handler" in signals
    ):
        return set_deterministic(
            InputChannel.web_content,
            signals,
            "browser/message source + dom sink"
        )

    # 5) Repo checkout (ultra-conservative)
    signals = _collect_repo_signals(evidence)
    if "repo_content_ingested" in signals and (
        "repo_content_read_as_data" in signals or "ci_context_marker" in signals
    ):
        return set_deterministic(
            InputChannel.repo_checkout,
            signals,
            "repo/ci content ingested"
        )

    # else remains unknown


# === Signal Collection Helpers ===

def _collect_websocket_signals(evidence: Evidence) -> list[str]:
    """Collect WebSocket signals from evidence."""
    signals = []

    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    # websocket_registration
    ws_patterns = [
        r'@app\.websocket\(',
        r'WebSocket\(',
        r'websocket_route\(',
        r'\.on\(["\']connection["\']',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in ws_patterns):
        signals.append("websocket_registration")

    # websocket_message_read
    msg_patterns = [
        r'\.receive\(',
        r'\.recv\(',
        r'message\.data',
        r'on_message\(',
        r'websocket\.receive_text',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in msg_patterns):
        signals.append("websocket_message_read")

    return signals


def _collect_http_signals(evidence: Evidence) -> list[str]:
    """Collect HTTP/REST signals from evidence."""
    signals = []

    # Signal 1: Route registration
    if _has_route_registration(evidence):
        signals.append("route_registration")

    # Signal 2a: Request data read
    if _has_request_data_read(evidence):
        signals.append("request_data_read")

    # Signal 2b: Framework parameter binding
    if _has_framework_param_binding(evidence):
        signals.append("framework_param_binding")

    return signals


def _has_route_registration(evidence: Evidence) -> bool:
    """Check if evidence contains route registration."""
    if evidence.route_registration:
        return True

    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    # FastAPI/Starlette: @app.get, @router.post
    # Flask: @app.route, @bp.route
    # Django: urlpatterns
    route_patterns = [
        r'@app\.(get|post|put|delete|patch)\(',
        r'@router\.(get|post|put|delete|patch)\(',
        r'@app\.route\(',
        r'@bp\.route\(',
        r'@blueprint\.route\(',
        r'path\(["\']',
        r'url\(',
    ]

    return any(re.search(p, snippet, re.IGNORECASE) for p in route_patterns)


def _has_request_data_read(evidence: Evidence) -> bool:
    """Check if evidence reads request data."""
    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    # FastAPI: request.json(), request.form(), request.query_params
    # Flask: request.json, request.form, request.args
    # Django: request.POST, request.GET, request.body
    request_patterns = [
        r'request\.(json|form|query_params|data|body)\(',
        r'request\.(json|form|args|POST|GET|body)\b',
        r'await\s+request\.json',
        r'request\.query\[',
        r'request\.form\[',
    ]

    return any(re.search(p, snippet, re.IGNORECASE) for p in request_patterns)


def _has_framework_param_binding(evidence: Evidence) -> bool:
    """
    Check if framework binds route params to handler args.

    Uses route template params ∩ handler args intersection.
    Tier 1: AST-based (preferred)
    Tier 2: Heuristic fallback
    """
    # Tier 1: AST-based (preferred)
    if evidence.symbol_info and evidence.route_registration:
        route_params = _extract_route_params(evidence.route_registration)
        handler_args = _extract_handler_args(evidence.symbol_info)

        # If route params overlap with handler args, binding detected
        if route_params & handler_args:
            return True

    # Tier 2: Heuristic fallback
    if evidence.route_registration and evidence.handler_snippet:
        # Extract params from route template
        route_params = _extract_route_params(evidence.route_registration)

        # Extract args from handler signature
        handler_match = re.search(r'def\s+\w+\s*\(([^)]+)\)', evidence.handler_snippet)
        if handler_match:
            args_str = handler_match.group(1)
            # Extract parameter names (before : or , or end)
            handler_args = set(re.findall(r'(\w+)\s*(?::|,|$)', args_str))
            # Remove common framework params
            handler_args -= {"self", "cls", "request", "response"}

            if route_params & handler_args:
                return True

    return False


def _extract_route_params(route: str) -> set[str]:
    """Extract parameter names from route template."""
    params = set()
    # FastAPI/Starlette: {user_id}
    params |= set(re.findall(r'\{(\w+)\}', route))
    # Flask: <user_id> or <int:user_id>
    params |= set(re.findall(r'<(?:\w+:)?(\w+)>', route))
    # Express/other: :user_id
    params |= set(re.findall(r':(\w+)', route))

    return params


def _extract_handler_args(symbol_info: dict) -> set[str]:
    """Extract function argument names from symbol info."""
    args = set()

    if "args" in symbol_info:
        for arg in symbol_info["args"]:
            if isinstance(arg, dict) and "name" in arg:
                args.add(arg["name"])
            elif isinstance(arg, str):
                args.add(arg)

    # Remove common framework params
    args -= {"self", "cls", "request", "response"}

    return args


def _collect_file_signals(evidence: Evidence) -> list[str]:
    """Collect file input signals from evidence."""
    signals = []

    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    # file_upload_api
    upload_patterns = [
        r'UploadFile',
        r'File\(',
        r'request\.files',
        r'MultipartForm',
        r'upload',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in upload_patterns):
        signals.append("file_upload_api")

    # external_file_read
    read_patterns = [
        r'\.read\(',
        r'open\(',
        r'Path\(',
        r'\.load\(',
        r'\.loads\(',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in read_patterns):
        signals.append("external_file_read")

    # file_parse_operation
    parse_patterns = [
        r'json\.load',
        r'yaml\.load',
        r'xml\.parse',
        r'csv\.reader',
        r'pickle\.load',
        r'parse\(',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in parse_patterns):
        signals.append("file_parse_operation")

    return signals


def _collect_web_signals(evidence: Evidence) -> list[str]:
    """Collect web content (browser-side) signals from evidence."""
    signals = []

    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    # dom_sink_use
    dom_patterns = [
        r'innerHTML',
        r'outerHTML',
        r'document\.write',
        r'eval\(',
        r'\.html\(',
        r'\.append\(',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in dom_patterns):
        signals.append("dom_sink_use")

    # browser_source_read
    browser_patterns = [
        r'location\.search',
        r'location\.hash',
        r'document\.cookie',
        r'localStorage',
        r'sessionStorage',
        r'window\.name',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in browser_patterns):
        signals.append("browser_source_read")

    # message_event_handler
    message_patterns = [
        r'postMessage',
        r'addEventListener\(["\']message["\']',
        r'onmessage\s*=',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in message_patterns):
        signals.append("message_event_handler")

    return signals


def _collect_repo_signals(evidence: Evidence) -> list[str]:
    """Collect repo/CI content signals from evidence."""
    signals = []

    snippet = (evidence.snippet or "") + (evidence.handler_snippet or "")

    # repo_content_ingested (looking at metadata might be better)
    repo_patterns = [
        r'clone',
        r'git\.',
        r'checkout',
        r'repository',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in repo_patterns):
        signals.append("repo_content_ingested")

    # repo_content_read_as_data
    read_patterns = [
        r'read_file',
        r'parse.*config',
        r'load.*manifest',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in read_patterns):
        signals.append("repo_content_read_as_data")

    # ci_context_marker
    ci_patterns = [
        r'CI[/_]',
        r'GITHUB_',
        r'GITLAB_',
        r'JENKINS',
        r'artifact',
    ]
    if any(re.search(p, snippet, re.IGNORECASE) for p in ci_patterns):
        signals.append("ci_context_marker")

    return signals
