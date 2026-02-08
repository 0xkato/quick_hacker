# Type Confusion Vulnerability Detection

Detect vulnerabilities where a value is accessed as a type different from its actual
type. Covers unsafe casts, union type punning, void* misuse, C++ dynamic_cast
bypasses, Rust transmute misuse, and JavaScript prototype chain manipulation.

## Methodology

### Step 1: Identify All Explicit Type Casts

Scan for C-style casts, reinterpret_cast, static_cast to unrelated types, and
pointer type conversions that change the pointed-to type.

```c
struct animal *a = get_animal();
struct dog *d = (struct dog *)a;  // SUSPECT: is a actually a dog?
d->bark_volume = 11;              // corrupts memory if a is a cat
```
```cpp
Base *b = get_base();
Derived *d = reinterpret_cast<Derived *>(b);  // no runtime check
d->derived_field = value;                      // UB if b is not Derived
```

### Step 2: Check C++ dynamic_cast Usage and Bypasses

```cpp
// VULNERABLE: result not checked
Derived *d = dynamic_cast<Derived *>(b);
d->method();  // nullptr dereference if b is not Derived

// SAFE: checked
if (auto d = dynamic_cast<Derived *>(b)) d->method();

// VULNERABLE: static_cast used to "optimize away" dynamic_cast
Derived *d = static_cast<Derived *>(b);  // no runtime check
```

### Step 3: Audit Union Type Punning

```c
// VULNERABLE: attacker controls union interpretation
union converter { uint64_t as_int; void *as_ptr; };
union converter c;
c.as_int = untrusted_value;
read_data(c.as_ptr);  // attacker controls pointer

// VULNERABLE: discriminated union with incorrect tag
struct variant { enum { INT, STR, OBJ } type; union { int64_t i; char *s; } val; };
// If attacker corrupts type field, s is read as i or vice versa
```

### Step 4: Check void* Callback Context Patterns

C APIs pass user data as `void*`, cast back in callbacks. Wrong type = corruption.

```c
void on_timer(void *ctx) {
    struct timer_data *td = (struct timer_data *)ctx;
    td->fire_count++;  // corrupts memory if ctx is not timer_data
}
// BUG: passing connection* where timer_data* is expected
register_timer(on_timer, conn);
```

### Step 5: Detect Rust transmute Misuse

```rust
// VULNERABLE: violates String's UTF-8 invariant
let v: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF];
let s: String = unsafe { std::mem::transmute(v) };
// s.as_str() methods assume UTF-8 -> UB

// VULNERABLE: transmuting to extend lifetime
let s = String::from("hello");
let r: &'static str = unsafe { std::mem::transmute(s.as_str()) };
drop(s);       // backing memory freed
println!("{}", r);  // dangling reference

// SAFE: same size, no invariants to violate
let x: u32 = 42;
let bytes: [u8; 4] = unsafe { std::mem::transmute(x) };
```

### Step 6: Analyze JavaScript Prototype Chain Type Confusion

```javascript
// Prototype pollution -> type confusion
Object.prototype.role = 'admin';
isAdmin({});  // true for every object

// Constructor spoofing
const fake = { constructor: SafeBuffer, data: payload };
fake instanceof SafeBuffer;  // true if SafeBuffer uses Symbol.hasInstance
```

### Step 7: Check Tagged Pointer and Discriminant Integrity

Systems using tags must validate before accessing the payload. Corrupted tags cause
type confusion.

```c
struct tagged_value { uint8_t tag; uint8_t data[63]; };
// If overflow in data[] corrupts tag:
switch (tv->tag) {
    case TAG_STRING: handle_string((char *)tv->data); break;
    case TAG_FUNCPTR: ((void (*)(void))tv->data)(); break;
    // Corrupted tag changes string data to function pointer call
}
```

## Decision Tree

```
Type cast or reinterpretation identified
  |
  v
Is the source type guaranteed compatible with target on ALL paths?
  |YES --> SAFE
  |NO
  v
Is there a runtime type check (dynamic_cast, tag, instanceof) BEFORE cast?
  |YES --> Is the check result verified before use?
  |         |YES --> SAFE
  |         |NO  --> VULNERABLE (High — nullptr deref)
  |NO
  v
Is the source value attacker-influenced?
  |YES --> VULNERABLE (Critical)
  |NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: Browser Engine DOM Type Confusion

```cpp
class Node { public: enum NodeType { ELEMENT, TEXT }; NodeType m_type; };
class Element : public Node {
public:
    std::map<std::string, std::string> m_attributes;
    void setAttribute(const std::string &n, const std::string &v) { m_attributes[n] = v; }
};

void processNode(Node *node) {
    if (node->type() == Node::ELEMENT) {
        Element *elem = static_cast<Element *>(node);  // no verification
        elem->setAttribute("processed", "true");
        // If m_type was corrupted (via separate bug), node is Text
        // but treated as Element -> writes to invalid memory offset
    }
}
```

**Why vulnerable:** static_cast blindly reinterprets the object. If m_type is
corrupted via a separate bug, a Text node is treated as Element. Writing to
m_attributes on a Text object corrupts arbitrary memory.

**Impact:** Arbitrary code execution via vtable confusion or controlled corruption.

**Fix:**
```cpp
void processNode(Node *node) {
    if (auto elem = dynamic_cast<Element *>(node)) {
        elem->setAttribute("processed", "true");
    }
}
```

### Example 2: Rust transmute Violating UTF-8 Invariant

```rust
pub fn fast_lowercase(input: &[u8]) -> String {
    let mut buf = input.to_vec();
    for b in &mut buf {
        if *b >= b'A' && *b <= b'Z' { *b += 32; }
    }
    unsafe { String::from_utf8_unchecked(buf) }  // assumes valid UTF-8
}
let s = fast_lowercase(untrusted_network_bytes);
// s may contain invalid UTF-8 -> UB in str methods
```

**Why vulnerable:** `String::from_utf8_unchecked` (equivalent to transmute) creates
a String from potentially non-UTF-8 bytes. String methods assume UTF-8 validity.
Iterating chars() or slicing at invalid boundaries causes UB.

**Impact:** Undefined behavior in safe code. OOB reads, incorrect slicing.

**Fix:**
```rust
pub fn fast_lowercase(input: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    let mut buf = input.to_vec();
    for b in &mut buf { if *b >= b'A' && *b <= b'Z' { *b += 32; } }
    String::from_utf8(buf)  // validates UTF-8
}
```

### Example 3: C void* Callback Context Mismatch

```c
struct auth_context { char username[64]; uint8_t session_key[32]; int priv_level; };
struct file_context { int fd; size_t offset; size_t length; };

void handle_upload(void *ctx, const char *body) {
    struct file_context *fc = (struct file_context *)ctx;
    lseek(fc->fd, fc->offset, SEEK_SET);
    write(fc->fd, body, fc->length);
}

void setup_routes(struct http_handler *h) {
    struct auth_context *auth = create_auth_context();
    h[0].callback = handle_upload;
    h[0].context = auth;  // BUG: auth_context where file_context expected
}
```

**Why vulnerable:** handle_upload interprets auth_context bytes as file_context
fields. The fd field overlaps with username bytes, offset with session_key. Attacker
controls username, so controls where and how much is written.

**Impact:** Arbitrary file write with attacker-controlled fd, offset, and length.

**Fix:**
```c
struct handler_context {
    enum { CTX_AUTH, CTX_FILE } type;
    union { struct auth_context auth; struct file_context file; } data;
};
void handle_upload(void *ctx, const char *body) {
    struct handler_context *hc = ctx;
    assert(hc->type == CTX_FILE);
    struct file_context *fc = &hc->data.file;
    lseek(fc->fd, fc->offset, SEEK_SET);
    write(fc->fd, body, fc->length);
}
```

## Common False Positive Patterns

1. **Upcast to base class:** Derived* to Base* is always safe in C++ with public
   inheritance.
2. **char* to unsigned char*:** C standard explicitly allows accessing any object
   through character types.
3. **Type punning via memcpy:** `memcpy(&float_val, &int_val, 4)` is the standard-
   compliant way. Not a type confusion. BY_DESIGN.
4. **Rust numeric as-casts:** `x as u32` where x: i64 is defined truncation, not
   type confusion.
5. **Discriminated unions with validated tags:** If tag is set by trusted code and
   protected from corruption, dispatch is SAFE.
6. **C++ std::variant:** Throws bad_variant_access on wrong type access. Safe by
   design.
7. **Serialization with schema validation:** Deserialized data validated against
   schema before type cast. Safe.
