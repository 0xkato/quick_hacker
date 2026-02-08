# Format String Vulnerability Detection

Detect vulnerabilities where user-controlled input is passed as the format string
to printf-family functions. Format string attacks allow reading from and writing to
arbitrary memory via specifiers like %x, %p, %n, and positional arguments.

## Methodology

### Step 1: Identify All Format String Functions

```c
// Standard C
printf(fmt, ...);  fprintf(fp, fmt, ...);  sprintf(dst, fmt, ...);
snprintf(dst, sz, fmt, ...);  syslog(pri, fmt, ...);
// v-variants: vprintf, vfprintf, vsprintf, vsnprintf
// Windows: wprintf, _snprintf, StringCbPrintf
// C++ iostream is NOT vulnerable (no format strings)
```

### Step 2: Trace the Format String Argument to Its Source

Determine whether the format string originates from user input.

```c
char *msg = get_user_input();
printf(msg);             // VULNERABLE: user input is the format string
printf("%s\n", msg);     // SAFE: user input is an argument

#define FMT "Status: %d\n"
printf(FMT, status);     // SAFE: format is a compile-time constant
```

### Step 3: Check Indirect Format String Injection

User input may reach format strings through config files, environment variables,
or database fields.

```c
char *fmt = config_get("log_format");
fprintf(logfile, fmt, timestamp, message);  // VULNERABLE if config is writable

char *fmt = getenv("MSG_FORMAT");
if (fmt) printf(fmt);  // VULNERABLE
```

### Step 4: Assess Exploitability via %n Write Primitive

`%n` writes the number of bytes printed so far to a pointer argument on the stack.
Combined with positional arguments, it provides arbitrary write.

```c
// Attacker sends: "%08x.%08x.%08x.%08x.%n"
printf(user_input);  // reads stack values via %08x, writes via %n

// Positional: "%100c%7$n" writes 100 to address at stack position 7
```

### Step 5: Check for Write-Restricted Environments

glibc with `_FORTIFY_SOURCE=2` restricts `%n` when format string is not in read-only
memory. Information leaks via `%x/%p/%s` remain possible. Do not classify as SAFE
just because `%n` is blocked.

### Step 6: Analyze Python Format String Risks

Python `format()` with user-controlled format specs can access object attributes.

```python
user_template = request.form['template']
output = user_template.format(user=current_user)
# Attacker: "{user.__class__.__init__.__globals__}" -> leaks secrets

# SAFE: user input as argument, not format string
output = "Hello, {}!".format(user_input)
```

### Step 7: Understand Why Rust format! Is Safe

Rust format macros parse the format string at compile time. The format string must
be a string literal -- it cannot be a runtime variable.

```rust
println!("Hello, {}", user_input);  // SAFE: format is literal
let fmt = get_input();
println!(fmt);  // COMPILE ERROR: format argument must be a string literal
```

### Step 8: Check Wrapper Functions

Custom logging functions that forward to printf-family inherit the vulnerability.

```c
void log_error(const char *fmt, ...) {
    va_list args; va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
log_error(user_message);                    // VULNERABLE
log_error("Conn from %s failed", addr);     // SAFE
```

Look for `__attribute__((format(printf, N, M)))` annotations -- they help compilers
warn but do not prevent runtime exploitation.

## Decision Tree

```
printf-family call identified
  |
  v
Is the format string a compile-time constant?
  |YES --> SAFE
  |NO
  v
Can the format string be influenced by external input?
  |NO --> HARDENED (Low) — internal source, logic bug only
  |YES
  v
Is %n available? (no FORTIFY_SOURCE)
  |YES --> VULNERABLE (Critical — arbitrary write)
  |NO  --> VULNERABLE (High — info leak via %x/%p/%s)
```

## Real-World Examples

### Example 1: Syslog Format String in Network Daemon

```c
void handle_client(int sock) {
    char ident[256];
    int n = recv(sock, ident, sizeof(ident) - 1, 0);
    if (n <= 0) return;
    ident[n] = '\0';
    syslog(LOG_INFO, ident);  // VULNERABLE: ident is the format string
}
```

**Why vulnerable:** Client-supplied string is passed directly as the format string.
Attacker sends `"%08x.%08x.%08x.%08x.%n"`. syslog internally calls vsprintf with
this format, reading stack values and writing via `%n`.

**Impact:** Remote code execution via `%n` overwriting GOT entry or return address.

**Fix:**
```c
syslog(LOG_INFO, "%s", ident);  // ident is now an argument, not the format
```

### Example 2: Python Template Injection via format()

```python
SECRET_KEY = "super-secret-key-12345"

class User:
    def __init__(self, name, role):
        self.name = name
        self.role = role

@app.route('/welcome')
def welcome():
    template = request.args.get('template', 'Welcome, {user.name}!')
    user = User(name="Alice", role="admin")
    return template.format(user=user)
```

**Why vulnerable:** Attacker controls `template` parameter. Python's str.format()
allows attribute access via dot notation. Sending
`{user.__class__.__init__.__globals__}` leaks all globals including SECRET_KEY.

**Impact:** Information disclosure (secrets, config). Potential RCE through MRO chain
traversal to callable objects.

**Fix:**
```python
@app.route('/welcome')
def welcome():
    user = User(name="Alice", role="admin")
    return f"Welcome, {escape(user.name)}!"  # no user-controlled format string
```

### Example 3: Custom Logging Wrapper Used With Raw Request Data

```c
void app_log(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

void process_request(request_t *req) {
    if (req->method == METHOD_UNKNOWN) {
        app_log(LOG_WARN, req->raw_line);  // raw HTTP line as format string
        return;
    }
}
```

**Why vulnerable:** `req->raw_line` is attacker-controlled (raw HTTP request).
Attacker sends `"GET %x%x%x%x%n HTTP/1.1"`. The format attribute generates
compiler warnings only if enabled and not suppressed.

**Impact:** Code execution via `%n`, or information leak to log file via `%x/%p`.

**Fix:**
```c
app_log(LOG_WARN, "Unknown method in request: %s", req->raw_line);
```

## Common False Positive Patterns

1. **String literal format strings:** `printf("Hello %s\n", name)` -- format is a
   literal, name is an argument. No vulnerability regardless of name's content.
2. **Gettext/i18n translated strings:** `printf(gettext("Hello %s"), name)` --
   translation files are typically trusted. HARDENED (Low) unless translation source
   is attacker-accessible.
3. **Compile-time concatenated literals:** `printf("Error " CODE_STR ": %d\n", err)`
   where CODE_STR is a `#define`. Concatenation at compile time produces a literal.
4. **Rust format macros:** `println!("{}", user_input)` is always safe. Format string
   parsed at compile time.
5. **C++ iostream:** `std::cout << user_input` has no format string interpretation.
6. **Go fmt with literal format:** `fmt.Printf("%v", userInput)` is safe. Go has no
   `%n` equivalent. `fmt.Printf(userInput)` is HARDENED (Low) -- info leak at most.
7. **Read-only config baked into binary:** Format string in `.rodata` section cannot
   be modified at runtime. SAFE.
