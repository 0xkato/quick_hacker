# Double-Free Detection

Detect double-free vulnerabilities where the same heap allocation is passed to
free()/delete more than once. Double-frees corrupt heap metadata and are reliably
exploitable on most allocators.

## Methodology

### Step 1: Map Every Allocation to All Possible Deallocation Sites

For each allocation, enumerate every free/delete that could receive that pointer.
Include all branches, error paths, cleanup labels, and destructor calls.

```c
char *buf = malloc(256);
if (error_condition) {
    free(buf);          // site 1
    goto cleanup;
}
process(buf);
cleanup:
    free(buf);          // site 2 — double-free when error_condition is true
```

### Step 2: Identify Ownership Transfers and Shared Ownership

Determine who owns the allocation at each point. Double-free occurs when two owners
both free the same memory.

```c
char *data = malloc(100);
send_to_worker(data);  // worker frees data
free(data);            // caller also frees — double-free
```

### Step 3: Analyze Conditional Free Without Null Guard

```c
void cleanup(context_t *ctx) {
    if (ctx->needs_cleanup) {
        free(ctx->data);  // ctx->data not set to NULL
    }
}
cleanup(ctx); cleanup(ctx);  // double-free if needs_cleanup still true
```

### Step 4: Check Error-Path Cleanup Sequences (goto cleanup)

The single most common source of double-frees in C.

```c
int init_system() {
    res_a = alloc_a();
    if (!res_a) goto fail;
    res_b = alloc_b();
    if (!res_b) { free(res_a); goto fail; }  // frees res_a
    res_c = alloc_c();
    if (!res_c) goto fail;
    return 0;
fail:
    free(res_a);  // double-free of res_a when res_b alloc failed
    free(res_b); free(res_c);
    return -1;
}
```

### Step 5: Detect C++ Double-Delete via Raw + Smart Pointer Mixing

```cpp
Widget *w = new Widget();
std::shared_ptr<Widget> sp(w);
delete w;    // manual delete
// sp goes out of scope -> delete again -> double-free

// Also: two shared_ptrs from same raw pointer (independent ref counts)
std::shared_ptr<Widget> sp1(w);
std::shared_ptr<Widget> sp2(w);  // both will delete w
```

### Step 6: Audit Rust Unsafe for Manual Dealloc

```rust
unsafe {
    let raw = Box::into_raw(Box::new(42));
    let b1 = Box::from_raw(raw);
    let b2 = Box::from_raw(raw);  // two Boxes from same pointer
    // Both drop -> double-free
}
```

### Step 7: Check Destructor Re-Entrance and Exception Paths

In C++, if destructor cleanup code throws, stack unwinding may re-destroy objects.

```cpp
~Resource() {
    delete data;
    data = nullptr;
    log_cleanup();  // if this throws, outer cleanup re-runs destructors
}
```

## Decision Tree

```
free()/delete for pointer P identified
  |
  v
Can P reach another free()/delete on any path without reassignment?
  |NO --> SAFE
  |YES
  v
Is P set to NULL between the two frees with a NULL check before second?
  |YES --> SAFE
  |NO
  v
Is the second free on an error/cleanup path?
  |NO --> VULNERABLE (Critical)
  |YES
  v
Is the error path reachable from normal operation?
  |YES --> VULNERABLE (Critical)
  |NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: Goto Cleanup Double-Free

```c
int tls_handshake(tls_ctx *ctx) {
    uint8_t *client_hello = NULL, *server_cert = NULL;
    client_hello = parse_client_hello(ctx);
    if (!client_hello) return -1;
    server_cert = load_certificate(ctx);
    if (!server_cert) {
        free(client_hello);  // first free
        goto error;
    }
    if (verify_signature(client_hello, server_cert) < 0) goto error;
    free(client_hello); free(server_cert);
    return 0;
error:
    free(client_hello);  // double-free when server_cert was NULL
    free(server_cert);
    return -1;
}
```

**Why vulnerable:** When load_certificate fails, client_hello is freed then goto
jumps to error label which frees it again. Pointer was not nulled.

**Impact:** Heap corruption. On glibc, corrupts tcache/fastbin freelist. Attacker
controlling TLS handshake achieves arbitrary write.

**Fix:**
```c
int tls_handshake(tls_ctx *ctx) {
    uint8_t *client_hello = NULL, *server_cert = NULL;
    client_hello = parse_client_hello(ctx);
    if (!client_hello) return -1;
    server_cert = load_certificate(ctx);
    if (!server_cert) goto error;
    if (verify_signature(client_hello, server_cert) < 0) goto error;
    free(client_hello); free(server_cert); return 0;
error:
    free(client_hello); free(server_cert); return -1;
    // Initialize to NULL, single cleanup path — free(NULL) is a safe no-op
}
```

### Example 2: C++ shared_ptr Double Ownership

```cpp
void setup() {
    Connection *c = new Connection("db.example.com");
    ConnectionPool pool1, pool2;
    pool1.add(std::shared_ptr<Connection>(c));
    pool2.add(std::shared_ptr<Connection>(c));  // independent ref counts!
    // Both pools destroy c independently -> double-free
}
```

**Why vulnerable:** Each shared_ptr from a raw pointer creates an independent
reference count. Both reach zero, both call delete.

**Impact:** Double-free heap corruption in connection pool destruction.

**Fix:**
```cpp
void setup() {
    auto c = std::make_shared<Connection>("db.example.com");
    pool1.add(c); pool2.add(c);  // shared ref count, freed once
}
```

### Example 3: Rust Unsafe Box::from_raw Called Twice

```rust
fn process_ffi(raw: *mut Config) {
    let config_a = unsafe { Box::from_raw(raw) };
    validate(&config_a);
    let config_b = unsafe { Box::from_raw(raw) };  // takes ownership again
    apply(&config_b);
    // Both Boxes drop -> double-free
}
```

**Why vulnerable:** `Box::from_raw` takes ownership. Calling it twice on the same
pointer creates two Boxes that each call dealloc when dropped.

**Impact:** Heap corruption, arbitrary code execution.

**Fix:**
```rust
fn process_ffi(raw: *mut Config) {
    let config = unsafe { Box::from_raw(raw) };  // take ownership once
    validate(&config);
    apply(&config);
    // Single drop
}
```

## Common False Positive Patterns

1. **Free then NULL then guarded free:** `free(p); p = NULL; ... if (p) free(p);`
   -- second free is guarded, safe.
2. **Realloc receives the pointer:** `p = realloc(p, sz)` frees old allocation
   internally but `p` is not freed again elsewhere.
3. **Separate allocations to same variable:** `p = malloc(10); free(p); p =
   malloc(20); free(p);` -- each free acts on a different allocation.
4. **Custom allocator with idempotent free:** Pool allocators that track freed
   blocks and ignore redundant frees. BY_DESIGN.
5. **Reference-counted free:** "Free" decrements refcount, only deallocates at
   zero. Multiple calls are expected.
6. **Destructor with internal null guard:** `if (ptr_) { delete ptr_; ptr_ =
   nullptr; }` -- safe against double-destruction of the member.
7. **Test harness intentional double-free:** Testing allocator hardening.
   BY_DESIGN in test context.
