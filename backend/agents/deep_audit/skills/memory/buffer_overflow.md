# Buffer Overflow Detection

Detect out-of-bounds reads and writes across stack buffers, heap allocations, and
array accesses. Covers stack smashing, heap corruption, off-by-one errors, and
unsafe unbounded copy functions.

## Methodology

### Step 1: Identify All Buffer Declarations and Their Sizes

Locate every fixed-size buffer and dynamic allocation. Record the declared or
computed size for each.

```c
char buf[64];                       // stack — size 64
char *p = malloc(n);                // heap — size n
std::vector<int> v(100);            // C++ — dynamic, tracked internally
```
```rust
let mut buf: [u8; 64] = [0u8; 64]; // Rust unsafe fixed buffer
let ptr = alloc(Layout::from_size_align(n, 1).unwrap()); // raw allocation
```

### Step 2: Trace All Write Operations Into Those Buffers

Enumerate every write path: direct indexing, pointer arithmetic, memcpy/strcpy/
sprintf, and loop-based writes.

```c
strcpy(buf, user_input);                       // unbounded — SUSPECT
strncpy(buf, src, sizeof(src));                // wrong size arg — SUSPECT
sprintf(buf, "Hello %s", name);                // unbounded — SUSPECT
snprintf(buf, sizeof(buf), "Hello %s", name);  // correct bounded copy
```

### Step 3: Compare Write Length Against Buffer Capacity

Flag any case where `max_write_length > buffer_size` or where the write length is
user-controlled and unchecked.

```c
memcpy(buf, src, n);                    // VULNERABLE if n > 64
memcpy(buf, src, MIN(n, sizeof(buf)));  // SAFE
```

### Step 4: Check Loop-Based Buffer Fills

Verify loop bounds use strictly less-than (not less-than-or-equal) the buffer size.

```c
for (int i = 0; i <= sizeof(buf); i++)  // off-by-one: <= should be <
    buf[i] = src[i];                     // writes 1 past end
```

### Step 5: Analyze Pointer Arithmetic Writes

Track pointer offsets and compare against the allocation base and size.

```c
char *end = buf + sizeof(buf);
char *p = buf;
while (*src && p < end) *p++ = *src++;
// Missing null terminator if p == end — off-by-one read later
```

### Step 6: Check Rust Unsafe Blocks for Bounds Bypass

`unsafe` blocks with raw pointers or `get_unchecked` bypass safe bounds checks.

```rust
unsafe {
    let val = *slice.get_unchecked(index);   // no bounds check
    std::ptr::write(ptr.add(offset), value); // raw pointer write
}
```

### Step 7: Check Python C Extensions

```c
static PyObject* process(PyObject* self, PyObject* args) {
    const char *data; Py_ssize_t len; char local_buf[256];
    PyArg_ParseTuple(args, "s#", &data, &len);
    memcpy(local_buf, data, len);  // VULNERABLE: len can exceed 256
}
```

## Decision Tree

```
Buffer write identified
  |
  v
Is write target size statically known?
  |YES          |NO
  v              v
Is write size   Is alloc size validated against write size?
bounded to       |YES    |NO --> VULNERABLE (High)
target size?     v       v
  |YES  |NO    SAFE
  v      v
SAFE   Is write size from user-controlled input?
        |YES                |NO
        v                    v
  VULNERABLE (Critical)    Are source and dest sizes guaranteed equal?
                            |YES    |NO --> VULNERABLE (High)
                            v
                           SAFE
```

## Real-World Examples

### Example 1: Stack Buffer Overflow via gets()

```c
void login() {
    char username[32], password[32];
    printf("Username: "); gets(username);
    printf("Password: "); gets(password);
    if (check_credentials(username, password)) grant_access();
}
```

**Why vulnerable:** `gets()` reads until newline with no length limit. Input longer
than 31 bytes overwrites the saved frame pointer and return address.

**Impact:** Remote code execution via return address overwrite.

**Fix:**
```c
void login() {
    char username[32], password[32];
    if (!fgets(username, sizeof(username), stdin)) return;
    username[strcspn(username, "\n")] = '\0';
    if (!fgets(password, sizeof(password), stdin)) return;
    password[strcspn(password, "\n")] = '\0';
    if (check_credentials(username, password)) grant_access();
}
```

### Example 2: Heap Overflow via Miscalculated Allocation

```c
void parse_header(const uint8_t *data, size_t data_len) {
    struct header *hdr = (struct header *)data;
    char *buf = malloc(hdr->name_len);  // allocates for name only
    memcpy(buf, data + sizeof(*hdr), hdr->name_len + hdr->value_len);  // copies both
    process(buf); free(buf);
}
```

**Why vulnerable:** `malloc` allocates `name_len` bytes but `memcpy` copies
`name_len + value_len` bytes. The extra bytes corrupt adjacent heap metadata.

**Impact:** Heap corruption, arbitrary write primitive, code execution.

**Fix:**
```c
void parse_header(const uint8_t *data, size_t data_len) {
    struct header *hdr = (struct header *)data;
    size_t total = (size_t)hdr->name_len + (size_t)hdr->value_len;
    if (sizeof(*hdr) + total > data_len) return;
    char *buf = malloc(total);
    if (!buf) return;
    memcpy(buf, data + sizeof(*hdr), total);
    process(buf); free(buf);
}
```

### Example 3: Rust Unsafe get_unchecked Off-By-One

```rust
pub unsafe fn sum_elements(data: &[u32], count: usize) -> u32 {
    let mut total: u32 = 0;
    for i in 0..=count {  // inclusive range: 0..=count is count+1 iterations
        total += *data.get_unchecked(i);
    }
    total
}
// Called as: sum_elements(&v, v.len()) — reads one past the end
```

**Why vulnerable:** Inclusive range `0..=count` iterates `count + 1` times. With
`count = data.len()`, the last iteration reads `data[data.len()]`, one past the end.

**Impact:** Out-of-bounds read. Information leak, potential crash.

**Fix:**
```rust
pub fn sum_elements(data: &[u32]) -> u32 {
    data.iter().sum()
}
```

## Common False Positive Patterns

1. **Bounded copy with correct size:** `strncpy(dst, src, sizeof(dst) - 1)` with
   explicit null termination.
2. **Compile-time constant source shorter than destination:** `strcpy(buf64, "OK")`.
3. **Wrapper functions that enforce bounds internally:** Project-specific `safe_copy`
   that validates lengths before calling `memcpy`.
4. **VLA/alloca sized to input:** `char buf[n]; memcpy(buf, src, n)` -- buffer is
   exactly sized to the copy. Not an overflow (stack exhaustion is separate class).
5. **Sentinel-terminated loops with guaranteed sentinel:** Loop reads until null byte
   where input is guaranteed null-terminated by prior bounded copy.
6. **Realloc before write:** Buffer grown via `realloc` before appending, checked
   for failure.
7. **Rust safe indexing:** `slice[i]` in safe Rust panics on OOB, does not corrupt
   memory. Classify as SAFE for memory corruption.
