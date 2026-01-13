# Context: Django Framework

**This module is loaded when:**
- Confidence > 0.8 that codebase uses Django
- Finding is relevant to Django patterns

**Django-Specific Patterns:**

## ORM and SQL
- `Model.objects.filter()` - Parameterized by default (SAFE)
- `Model.objects.raw()` - Takes raw SQL (POTENTIALLY UNSAFE)
- `cursor.execute()` - Django DB cursor (check for f-strings)

## Request Handling
- `request.GET['param']` - Query parameters (user-controlled)
- `request.POST['field']` - Form data (user-controlled)
- `request.body` - Raw request body (user-controlled)
- `request.META['HTTP_X_CUSTOM']` - Headers (user-controlled)

## Authentication/Authorization
- `@login_required` - Requires authentication
- `request.user.is_authenticated` - Check if user is logged in
- `request.user` - Current authenticated user object
- Missing decorators = potentially unprotected route

## CSRF Protection
- Django has built-in CSRF protection (enabled by default)
- `@csrf_exempt` - DISABLES CSRF protection (security concern)

## Template Rendering
- `render(request, template, context)` - Safe (auto-escapes)
- `mark_safe()` - DISABLES auto-escaping (XSS risk)

## Common Pitfalls
- `.raw()` with f-strings → SQL injection
- Missing `@login_required` → Auth bypass
- `@csrf_exempt` → CSRF vulnerability
- `mark_safe(user_input)` → XSS
