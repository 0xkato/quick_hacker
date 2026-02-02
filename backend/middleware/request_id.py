"""Request ID middleware for request tracing and log correlation."""

import logging
import uuid
from contextvars import ContextVar
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Context variable to store request ID for the current request
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

# Header name for request ID
REQUEST_ID_HEADER = "X-Request-ID"


def get_request_id() -> Optional[str]:
    """Get the current request ID from context.

    Returns:
        The request ID for the current request, or None if not in a request context.
    """
    return request_id_ctx.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware that generates and propagates request IDs.

    - If X-Request-ID header is present, uses that value
    - Otherwise generates a new UUID
    - Adds X-Request-ID to response headers
    - Makes request ID available via get_request_id() for logging
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Get existing request ID or generate new one
        request_id = request.headers.get(REQUEST_ID_HEADER)
        if not request_id:
            request_id = str(uuid.uuid4())[:12]  # Short UUID for readability

        # Store in context for access in handlers/services
        token = request_id_ctx.set(request_id)

        try:
            # Process request
            response = await call_next(request)

            # Add request ID to response headers
            response.headers[REQUEST_ID_HEADER] = request_id

            return response
        finally:
            # Reset context
            request_id_ctx.reset(token)


class RequestIDLogFilter(logging.Filter):
    """Logging filter that adds request_id to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id() or "-"
        return True
