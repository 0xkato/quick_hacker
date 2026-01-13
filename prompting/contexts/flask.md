# Context: Flask Framework

**This module is loaded when:**
- Confidence > 0.8 that codebase uses Flask
- Finding is relevant to Flask patterns

**Flask-Specific Patterns:**

## Request Handling
- `request.args.get('param')` - Query parameters (user-controlled)
- `request.form['field']` - Form data (user-controlled)
- `request.json['key']` - JSON body (user-controlled)
- `request.headers['X-Custom']` - Headers (user-controlled)

## Database
- Flask doesn't enforce ORM (can use SQLAlchemy, raw SQL, etc.)
- Check for string concatenation in SQL queries

## Authentication
- No built-in auth (uses extensions like Flask-Login)
- `@login_required` - Extension decorator for auth
- Missing decorator = potentially unprotected route

## Template Rendering
- `render_template()` - Jinja2 (auto-escapes by default)
- `Markup()` or `| safe` filter - DISABLES auto-escaping (XSS risk)

## Common Pitfalls
- f-string SQL queries → SQL injection
- Missing `@login_required` → Auth bypass
- `| safe` filter with user input → XSS
