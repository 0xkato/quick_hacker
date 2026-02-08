# Unsafe FFI Boundary Detection

Detect memory safety violations at foreign function interface boundaries where
different languages interact. FFI boundaries are where ownership models, lifetime
rules, null semantics, and string encodings collide. Covers Python ctypes/cffi,
Rust FFI, Node.js native addons, Go cgo, and Java JNI.

## Methodology

### Step 1: Identify All FFI Boundary Crossings

Enumerate every point where one language calls into another.

```rust
extern "C" { fn openssl_encrypt(data: *const u8, len: usize, out: *mut u8) -> i32; }
#[no_mangle]
pub extern "C" fn rust_process(data: *const u8, len: usize) -> i32 { /* ... */ }
```
```python
import ctypes
lib = ctypes.CDLL("libcrypto.so")
lib.encrypt.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
```
```go
/*
#include <openssl/evp.h>
#cgo LDFLAGS: -lcrypto
*/
import "C"
```

### Step 2: Check Ownership Transfer at Each Boundary

The critical FFI question: who owns the memory? Exactly one side must free it.

```rust
// VULNERABLE: Rust allocates, C frees with wrong allocator
#[no_mangle]
pub extern "C" fn create_string() -> *mut c_char {
    CString::new("hello").unwrap().into_raw()  // Rust allocator
    // If C calls free() on this -> heap corruption (allocator mismatch)
}

// SAFE: provide matching free function
#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}
```

### Step 3: Verify Null Pointer Handling

Different languages handle null differently. Rust references cannot be null.

```rust
// VULNERABLE: C may pass NULL
#[no_mangle]
pub extern "C" fn process(data: *const u8, len: usize) -> i32 {
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    // from_raw_parts requires non-null -> UB if data is NULL
    slice.iter().sum::<u8>() as i32
}

// SAFE:
if data.is_null() || len == 0 { return -1; }
```

### Step 4: Check String Encoding Mismatches

C: null-terminated bytes. Rust: UTF-8, no null terminator. Java/JS: UTF-16.

```rust
// VULNERABLE: interior null in Rust string truncates at C boundary
let s = "hello\0world";
let ptr = s.as_ptr() as *const c_char;
unsafe { C_function(ptr); }  // C sees "hello" — truncated

// VULNERABLE: C string not valid UTF-8, Rust assumes it is
let s = unsafe { CStr::from_ptr(msg).to_str().unwrap() };  // panics if not UTF-8
// Use to_string_lossy() instead
```

```java
// JNI "modified UTF-8" is NOT standard UTF-8
const char *str = (*env)->GetStringUTFChars(env, jstr, NULL);
process_utf8(str);  // SUSPECT: modified UTF-8 != real UTF-8
```

### Step 5: Audit Lifetime Mismatches

Borrowed references crossing FFI may be held longer than the borrow is valid.

```rust
fn register_callback(registry: &mut Registry) {
    let data = vec![1, 2, 3];
    unsafe { C_register(data.as_ptr(), data.len()); }
    // data dropped here — C holds dangling pointer
}
```
```python
def setup():
    buf = ctypes.create_string_buffer(1024)
    lib.register_buffer(buf)  # C stores pointer
    # buf goes out of scope -> GC may collect -> C holds dangling pointer
```

### Step 6: Check Error Handling Across FFI

Panics/exceptions cannot propagate across FFI. A Rust panic through C is UB.

```rust
// VULNERABLE: panic across FFI
#[no_mangle]
pub extern "C" fn callback(data: *const u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let _ = slice[0];  // panic if empty -> unwinds through C -> UB
}

// SAFE: catch_unwind at boundary
#[no_mangle]
pub extern "C" fn callback(data: *const u8, len: usize) -> i32 {
    std::panic::catch_unwind(|| {
        if data.is_null() || len == 0 { return -1; }
        unsafe { std::slice::from_raw_parts(data, len) }[0] as i32
    }).unwrap_or(-1)
}
```

### Step 7: Verify Buffer Size Agreements

Both sides must agree on size semantics (bytes vs elements, null terminator).

```c
// Node.js N-API
size_t len;
napi_get_value_string_utf8(env, args[0], NULL, 0, &len);  // excludes null
char *buf = malloc(len);      // VULNERABLE: no room for null terminator
napi_get_value_string_utf8(env, args[0], buf, len, &len);  // truncates
// Fix: malloc(len + 1)
```

## Decision Tree

```
FFI boundary crossing identified
  |
  v
Memory allocated on one side, accessed/freed on other?
  |NO --> Check null handling, encoding, error propagation
  |YES
  v
Same allocator or paired alloc/free provided?
  |YES --> Check lifetime guarantees
  |NO  --> VULNERABLE (High — allocator mismatch)

Lifetime check:
  v
Does foreign side store pointer beyond the call?
  |NO --> SAFE (transient use)
  |YES
  v
Is pointer's backing memory guaranteed to outlive foreign usage?
  |YES --> SAFE
  |NO  --> VULNERABLE (Critical — dangling pointer across FFI)
```

## Real-World Examples

### Example 1: Python ctypes Lifetime Escape to Worker Thread

```python
def launch_worker(config_str: str):
    buf = ctypes.create_string_buffer(config_str.encode('utf-8'))
    lib.start_worker(buf, len(config_str))
    # buf goes out of scope -> GC may free
    # Worker thread reads freed memory
```

**Why vulnerable:** ctypes buffer is Python-managed. When the function returns, `buf`
has no references. GC frees underlying memory. The C worker thread reads from a
dangling pointer.

**Impact:** Use-after-free. Worker reads corrupted data or crashes. Information leak
or code execution in server context.

**Fix:**
```python
class Worker:
    def __init__(self, config_str):
        self._buf = ctypes.create_string_buffer(config_str.encode('utf-8'))
        self._handle = lib.start_worker(self._buf, len(config_str))
    def stop(self):
        lib.stop_worker(self._handle)
        self._buf = None  # safe to release after stop
```

### Example 2: Rust FFI Allocator Mismatch

```rust
#[no_mangle]
pub extern "C" fn get_version() -> *mut c_char {
    CString::new("1.2.3").unwrap().into_raw()  // Rust allocator
}
```
```c
char *ver = get_version();
printf("Version: %s\n", ver);
free(ver);  // VULNERABLE: C's free() on Rust-allocated memory
```

**Why vulnerable:** Rust may use a different allocator than C. On some platforms they
happen to share one (masking the bug), but with jemalloc or a custom allocator, free()
receives a pointer from a different heap, corrupting both allocators.

**Impact:** Heap corruption. Undefined behavior regardless of platform.

**Fix:**
```rust
#[no_mangle]
pub extern "C" fn get_version() -> *mut c_char {
    CString::new("1.2.3").unwrap().into_raw()
}
#[no_mangle]
pub extern "C" fn free_version(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}
```

### Example 3: Go cgo CString Memory Leak

```go
func sendHeaders(headers map[string]string) {
    cHeaders := make([]C.header_t, 0, len(headers))
    for k, v := range headers {
        cHeaders = append(cHeaders, C.header_t{
            name:  C.CString(k),   // C.malloc'd
            value: C.CString(v),   // C.malloc'd
        })
    }
    C.process_headers(&cHeaders[0], C.int(len(cHeaders)))
    // VULNERABLE: CString allocations never freed -> unbounded leak
}
```

**Why vulnerable:** `C.CString()` calls `C.malloc()` internally. The returned
pointers must be freed with `C.free()`. This code leaks every string on every call.

**Impact:** Memory leak -> OOM denial of service in long-running server. Adding
premature `C.free()` before `process_headers` completes would convert to UAF.

**Fix:**
```go
func sendHeaders(headers map[string]string) {
    cHeaders := make([]C.header_t, 0, len(headers))
    cStrings := make([]*C.char, 0, len(headers)*2)
    for k, v := range headers {
        cn, cv := C.CString(k), C.CString(v)
        cStrings = append(cStrings, cn, cv)
        cHeaders = append(cHeaders, C.header_t{name: cn, value: cv})
    }
    C.process_headers(&cHeaders[0], C.int(len(cHeaders)))
    for _, s := range cStrings { C.free(unsafe.Pointer(s)) }
}
```

## Common False Positive Patterns

1. **Same allocator by platform convention:** Both sides use glibc malloc. Technically
   valid but fragile. Classify as HARDENED (Low).
2. **Transient pointer use:** Foreign function only reads pointer during the call,
   does not store it. No lifetime issue.
3. **Copy-in/copy-out:** FFI layer copies data (e.g., `C.GoString()` copies C string
   to Go string). Original can be freed immediately.
4. **Opaque handle pattern:** One side returns an integer/handle never dereferenced
   by the other, with paired create/destroy. Safe by design.
5. **Python bytes in single ctypes call:** Python holds a reference for the call
   duration. Safe for non-storing functions.
6. **JNI local references within native method:** Valid for the method's duration.
   Invalid after return, but safe within.
7. **Rust Box with repr(C) and paired from_raw:** `Box::into_raw` paired with
   `Box::from_raw` on the same side is the correct pattern.
