# Context: FastAPI Framework

**This module is loaded when:**
- Confidence > 0.8 that codebase uses FastAPI
- Finding is relevant to FastAPI patterns

**FastAPI-Specific Patterns:**

## Request Parameters
- `def route(param: str = Query(...))` - Query parameter (user-controlled)
- `def route(param: str = Path(...))` - Path parameter (user-controlled)
- `def route(body: Model = Body(...))` - Request body (user-controlled, Pydantic validated)

## Pydantic Validation
- FastAPI uses Pydantic for automatic validation
- Type annotations enforce validation (e.g., `param: int` auto-validates)
- Custom validators: `@validator` decorators
- Validation CAN be bypassed if using `.dict()` or `.json()` directly without validation

## Dependencies
- `Depends()` - Dependency injection (can include auth checks)
- Missing auth dependency = potentially unprotected route

## Authentication
- No built-in auth like Django
- Typically uses `Depends(get_current_user)` pattern
- Check for missing auth dependencies

## Common Pitfalls
- Bypassing Pydantic validation with raw dict access
- Missing auth dependencies on sensitive routes
- SQL injection if using raw SQL with user input (even if Pydantic validated)
