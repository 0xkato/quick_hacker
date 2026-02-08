# Uninitialized Memory Detection

Detect use of memory that has been allocated but never written to. Reading
uninitialized memory leaks stack/heap contents, produces non-deterministic behavior,
and can expose secrets (keys, pointers, canaries) to attackers.

## Methodology

### Step 1: Identify Local Variable Declarations Without Initializers

In C/C++, local (non-static) variables have indeterminate values unless initialized.

```c
int status;          // UNINITIALIZED
char name[64];       // UNINITIALIZED (all 64 bytes)
size_t offset = 0;   // initialized — safe

if (len > 10) status = parse_header(data, &offset);
return status;  // VULNERABLE on short-packet path (len <= 10)
```

### Step 2: Track Conditional Initialization Paths

Verify ALL paths leading to a read include the initialization.

```c
int result;
switch (op) {
    case OP_ADD: result = a + b; break;
    case OP_SUB: result = a - b; break;
    // No default — result uninitialized for unknown op
}
return result;  // VULNERABLE
```

```c
struct response resp;
resp.code = 200;
if (include_body) { resp.body = build_body(); resp.body_len = body_length; }
send_response(&resp);  // body/body_len uninitialized when !include_body
```

### Step 3: Check malloc vs calloc for Externally-Exposed Buffers

`malloc` returns uninitialized memory. For buffers sent over the network or to disk,
uninitialized bytes leak heap contents.

```c
char *resp = malloc(RESP_SIZE);
int n = snprintf(resp, RESP_SIZE, "OK %d", code);
write(fd, resp, RESP_SIZE);  // bytes after null terminator are uninitialized

// SAFE:
char *resp = calloc(1, RESP_SIZE);  // or: write(fd, resp, n);
```

### Step 4: Audit Rust MaybeUninit Usage

```rust
// VULNERABLE: assume_init before initialization
let x: i32 = unsafe { MaybeUninit::uninit().assume_init() };

// VULNERABLE: partial array initialization
let mut arr: [MaybeUninit<u32>; 100] = unsafe { MaybeUninit::uninit().assume_init() };
for i in 0..50 { arr[i] = MaybeUninit::new(i as u32); }
// Indices 50..100 are uninitialized
let slice: &[u32] = unsafe {
    std::slice::from_raw_parts(arr.as_ptr() as *const u32, 100)  // UB
};
```

### Step 5: Check Compiler-Dependent Zeroing Assumptions

Debug builds may zero stack memory; release builds do not. Code that "works" in
debug may leak in production.

```c
char buffer[1024];
// No memset — relies on implicit zeroing NOT guaranteed
strncat(buffer, "suffix", sizeof(buffer) - 1);
// strncat searches for null terminator — reads garbage in release
```

### Step 6: Detect Padding Byte Information Leaks

Structs with padding between members leak uninitialized bytes when serialized whole.

```c
struct wire_msg { uint8_t type; /* 3 padding bytes */ uint32_t length; };
struct wire_msg msg;
msg.type = MSG_HELLO;
msg.length = payload_len;
write(sock, &msg, sizeof(msg));  // leaks 3 padding bytes to network
```

### Step 7: Check Go and Java (Comparison)

Go zero-initializes all variables. Java initializes fields to zero/null/false. Neither
has uninitialized memory in managed code. However, cgo and JNI native code follow C
rules and are vulnerable.

```go
var x int   // Go: safe, x = 0
var s string // Go: safe, s = ""
```

## Decision Tree

```
Variable/buffer read identified
  |
  v
Guaranteed initialized on ALL paths reaching this read?
  |YES --> SAFE
  |NO
  v
Allocated with zeroing function? (calloc, memset, = {0})
  |YES --> SAFE
  |NO
  v
Does the read send data externally? (network, file, IPC, log)
  |YES --> VULNERABLE (High) — info leak
  |NO
  v
Value used in security decision? (auth, crypto, access control)
  |YES --> VULNERABLE (Critical)
  |NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: Kernel Stack Information Leak via ioctl

```c
long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct device_info info;
    info.version = DRIVER_VERSION;
    info.capabilities = get_caps();
    // info.reserved[64] NOT zeroed — contains kernel stack data
    if (copy_to_user((void __user *)arg, &info, sizeof(info)))
        return -EFAULT;
    return 0;
}
```

**Why vulnerable:** Stack-allocated struct is partially initialized. `copy_to_user`
copies the entire struct including uninitialized `reserved` array and padding bytes
containing kernel stack data.

**Impact:** Kernel memory disclosure. Leaks kernel pointers (defeats KASLR), crypto
keys, or other sensitive data to userspace.

**Fix:**
```c
long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct device_info info;
    memset(&info, 0, sizeof(info));  // zero EVERYTHING first
    info.version = DRIVER_VERSION;
    info.capabilities = get_caps();
    if (copy_to_user((void __user *)arg, &info, sizeof(info)))
        return -EFAULT;
    return 0;
}
```

### Example 2: Missing Default Branch Returns Uninitialized Pointer

```c
const char* status_string(int code) {
    const char *msg;
    switch (code) {
        case 200: msg = "OK"; break;
        case 404: msg = "Not Found"; break;
        case 500: msg = "Internal Error"; break;
    }
    return msg;  // uninitialized for code 301, 403, etc.
}
```

**Why vulnerable:** For any code not in the switch, `msg` is an uninitialized pointer.
Dereferencing it reads arbitrary memory as a string until a null byte.

**Impact:** Information leak (arbitrary memory read) or crash (segfault).

**Fix:**
```c
const char* status_string(int code) {
    switch (code) {
        case 200: return "OK";
        case 404: return "Not Found";
        case 500: return "Internal Error";
        default:  return "Unknown";
    }
}
```

### Example 3: Rust MaybeUninit with Early-Exit Deserialization

```rust
fn read_records(reader: &mut impl Read, count: usize) -> Vec<Record> {
    let mut records: Vec<MaybeUninit<Record>> = Vec::with_capacity(count);
    unsafe { records.set_len(count); }  // length set without initializing
    for i in 0..count {
        match Record::deserialize(reader) {
            Ok(r) => records[i] = MaybeUninit::new(r),
            Err(_) => break,  // remaining slots uninitialized
        }
    }
    unsafe { std::mem::transmute::<Vec<MaybeUninit<Record>>, Vec<Record>>(records) }
}
```

**Why vulnerable:** If deserialization fails partway, remaining slots are
uninitialized. Transmuting them to Record is UB. If Record has a String field,
uninitialized bytes become pointer/length/capacity, enabling arbitrary read/write.

**Impact:** Arbitrary memory access via uninitialized String internals.

**Fix:**
```rust
fn read_records(reader: &mut impl Read, count: usize) -> Vec<Record> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        match Record::deserialize(reader) {
            Ok(r) => records.push(r),
            Err(_) => break,
        }
    }
    records  // only contains successfully initialized records
}
```

## Common False Positive Patterns

1. **Go/Java managed code:** All variables zero-initialized by language spec.
2. **Aggregate initializer `= {0}`:** Zero-initializes entire struct including
   padding in C.
3. **Write-before-read in all branches:** Every branch initializes the variable
   before any read. Path-sensitive analysis confirms safety.
4. **memset immediately after malloc:** Equivalent to calloc — safe.
5. **Output parameters written by callee:** Function taking `int *out` always
   writes `*out` before returning success. Caller's uninitialized variable is set.
6. **Union with designated initializer:** Initializes one member. Reading another
   member is type punning, not uninitialized memory.
7. **Sanitizer paint values:** ASan/MSan use sentinel values (0xbe, 0xff) which are
   not meaningful initialization. Code appearing to work under sanitizers may still
   use uninitialized memory.
