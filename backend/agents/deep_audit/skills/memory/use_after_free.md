# Use-After-Free Detection

Detect access to memory after deallocation. Covers direct dereference after free(),
iterator invalidation, returning references to freed memory, and shared_ptr/weak_ptr
lifetime mismanagement.

## Methodology

### Step 1: Map All Allocation-Deallocation Pairs

For every malloc/new, find the corresponding free/delete. For RAII types, identify
scope boundaries where destructors run.

```c
char *p = malloc(128);
free(p);             // deallocation
printf("%s\n", p);   // UAF — p is dangling
```
```cpp
auto ptr = std::make_unique<Widget>();
Widget *raw = ptr.get();
ptr.reset();         // deallocation
raw->draw();         // UAF — raw is dangling
```

### Step 2: Trace All Post-Free Uses of Each Pointer

After each deallocation, trace every subsequent use of the pointer and any aliases.

```c
free(p);
char *alias = p;     // alias set before or after free
alias[0] = 'x';     // UAF via alias
```

### Step 3: Check Error Paths and Early Returns

The most common real-world UAF source: cleanup on error paths where execution
continues using the freed resource.

```c
int process(connection_t *conn) {
    if (validate(conn) < 0) {
        close_connection(conn);  // frees conn internals
        log_error("bad conn from %s", conn->addr);  // UAF
        return -1;
    }
}
```

### Step 4: Detect Iterator Invalidation

Modifying a container while iterating invalidates iterators.

```cpp
std::vector<int> v = {1, 2, 3, 4, 5};
for (auto it = v.begin(); it != v.end(); ++it) {
    if (*it == 3) {
        v.erase(it);  // invalidates it; ++it in loop header is UAF
    }
}

int &ref = v[0];
v.push_back(4);    // may reallocate
ref = 42;          // UAF if reallocation occurred
```

### Step 5: Audit shared_ptr / weak_ptr Patterns

```cpp
std::shared_ptr<Session> session = get_session();
Session *raw = session.get();
session_map.erase(session->id());  // may drop last shared_ptr
raw->process();                     // UAF if last ref was dropped
```

### Step 6: Check Rust Unsafe for Dangling Raw Pointers

```rust
let mut v = vec![1, 2, 3];
let ptr = v.as_ptr();
v.push(4);                        // may reallocate
unsafe { println!("{}", *ptr); }  // UAF if reallocated
```

### Step 7: Detect Returning References to Freed Memory

```c
char *get_name() {
    char *buf = malloc(64);
    snprintf(buf, 64, "user_%d", get_uid());
    free(buf);
    return buf;  // returns dangling pointer
}
```

## Decision Tree

```
Pointer/reference access identified
  |
  v
Has backing memory been freed on ALL paths reaching this access?
  |YES --> VULNERABLE (Critical)
  |NO
  v
Freed on SOME paths?
  |NO --> SAFE
  |YES
  v
Is the free path reachable from attacker-controlled input?
  |YES --> VULNERABLE (Critical)
  |NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: UAF in Event Handler — Missing Return After Free

```c
void handle_read(connection *conn) {
    char buf[4096];
    ssize_t n = read(conn->fd, buf, sizeof(buf));
    if (n <= 0) { destroy_connection(conn); return; }
    if (buf[0] == 'Q') {
        destroy_connection(conn);
        // Missing return — falls through!
    }
    conn->on_data(conn, buf, n);  // UAF when buf[0] == 'Q'
}
```

**Why vulnerable:** When buf[0] is 'Q', conn is freed but execution falls through
to the callback. The function pointer `conn->on_data` is read from freed memory.

**Impact:** Code execution. Attacker sprays heap to replace freed struct with
controlled data, hijacking the function pointer.

**Fix:**
```c
if (buf[0] == 'Q') { destroy_connection(conn); return; }
```

### Example 2: C++ Vector Iterator Invalidation in Callback

```cpp
void remove_expired(std::vector<std::shared_ptr<Timer>> &timers) {
    for (auto it = timers.begin(); it != timers.end(); ++it) {
        if ((*it)->expired()) {
            (*it)->cancel();   // may re-enter this function
            timers.erase(it);  // invalidates it; ++it is UAF
        }
    }
}
```

**Why vulnerable:** `erase()` invalidates `it`. The loop increment operates on an
invalid iterator. `cancel()` may also re-enter, causing concurrent modification.

**Impact:** Heap corruption, crash, potential code execution.

**Fix:**
```cpp
void remove_expired(std::vector<std::shared_ptr<Timer>> &timers) {
    std::vector<std::shared_ptr<Timer>> expired;
    auto new_end = std::remove_if(timers.begin(), timers.end(),
        [&](const auto &t) {
            if (t->expired()) { expired.push_back(t); return true; }
            return false;
        });
    timers.erase(new_end, timers.end());
    for (auto &t : expired) t->cancel();
}
```

### Example 3: Rust Raw Pointer Outlives Vec Reallocation

```rust
struct Cache {
    entries: Vec<Entry>,
    hot: *const Entry,  // raw pointer into entries vec
}
impl Cache {
    fn add(&mut self, e: Entry) {
        self.entries.push(e);  // may reallocate — hot becomes dangling
        self.hot = self.entries.last().unwrap() as *const Entry;
    }
    unsafe fn get_hot(&self) -> &Entry { &*self.hot }
    fn compact(&mut self) {
        self.entries.retain(|e| !e.stale);
        // self.hot not updated — dangling
    }
}
```

**Why vulnerable:** `self.hot` is a raw pointer into Vec's buffer. Any operation
that reallocates or shrinks the Vec invalidates it.

**Impact:** Read of freed memory, information leak, crash.

**Fix:**
```rust
struct Cache { entries: Vec<Entry>, hot_index: Option<usize> }
impl Cache {
    fn get_hot(&self) -> Option<&Entry> {
        self.hot_index.and_then(|i| self.entries.get(i))
    }
}
```

## Common False Positive Patterns

1. **Pointer nulled after free:** `free(p); p = NULL;` followed by null check
   before use. Safe through the nulled variable (aliases may still be dangerous).
2. **Realloc replacing the pointer:** `p = realloc(p, new_size)` — subsequent use
   of `p` is valid if realloc succeeded and return was checked.
3. **RAII destructor ordering:** C++ local variables destroyed in reverse declaration
   order. A reference from one local to an earlier-declared local is valid in scope.
4. **Arena allocators that defer deallocation:** Memory remains valid until the
   entire arena is destroyed.
5. **Move semantics leaving valid empty state:** After `std::move`, the source
   object still exists. Not UAF, though it may be a logic error.
6. **Shared ownership with guaranteed lifetime:** Function holding a `shared_ptr`
   copy while also using a raw pointer extracted from it.
7. **Weak reference with explicit validity check:** Code checking a generation
   counter or validity flag before dereferencing.
