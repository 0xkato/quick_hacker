# Context: Express.js Framework

**This module is loaded when:**
- Confidence > 0.8 that codebase uses Express.js (Node.js)
- Finding is relevant to Express patterns

**Express-Specific Patterns:**

## Request Handling
- `req.query.param` - Query parameters (user-controlled)
- `req.params.id` - Path parameters (user-controlled)
- `req.body.field` - Request body (user-controlled, needs body-parser)
- `req.headers['x-custom']` - Headers (user-controlled)

## Middleware
- `app.use(middleware)` - Middleware applies to all routes after it
- Auth middleware should run before sensitive routes
- Missing auth middleware = potentially unprotected route

## Database
- Varies (MongoDB, PostgreSQL, etc.)
- MongoDB: Check for NoSQL injection (e.g., `$where` operator with user input)
- PostgreSQL: Check for string concatenation in queries (parameterized queries use `$1, $2`)

## Template Rendering
- EJS: `<%= user_input %>` - Auto-escaped (safe)
- EJS: `<%- user_input %>` - NOT escaped (XSS risk)
- Handlebars: `{{ user_input }}` - Auto-escaped (safe)
- Handlebars: `{{{ user_input }}}` - NOT escaped (XSS risk)

## Common Pitfalls
- MongoDB `$where` with user input → NoSQL injection
- Missing auth middleware → Auth bypass
- `<%- %>` or `{{{ }}}` with user input → XSS
- `eval(user_input)` → Code injection
