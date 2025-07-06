# Crypto Scanner Fix Strategy

The crypto scanner has 100+ regex patterns compiled with unwrap(). Here are the options:

## Option 1: Lazy Static (Recommended)
Use `once_cell::sync::Lazy` to compile patterns once at startup:

```rust
use once_cell::sync::Lazy;

static DEPRECATED_HASH_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"...").expect("Invalid regex: description"),
        // ... more patterns
    ]
});
```

Pros:
- Patterns compiled once
- Panics at startup if patterns are invalid (fail-fast)
- No runtime overhead

Cons:
- Uses expect() instead of unwrap() (still panics but with message)

## Option 2: Result-based Constructor
Create a `try_new()` that returns `Result<Self, Error>`:

```rust
impl CryptoScanner {
    pub fn try_new() -> Result<Self, ScanError> {
        let deprecated_hash_patterns = vec![
            Regex::new(r"...")?,
            // ... more patterns
        ];
        
        Ok(Self {
            deprecated_hash_patterns,
            // ...
        })
    }
}
```

Pros:
- Proper error handling
- No panics
- Follows Rust best practices

Cons:
- API change (new() -> try_new())
- Need to update all call sites

## Option 3: Hardcoded Pattern Structs
Pre-validate patterns at compile time using const strings and lazy compilation.

## Recommendation:
Given that regex patterns are static and should never fail if written correctly, Option 1 (Lazy Static) is recommended. The patterns will be validated at startup, and any issues will be caught immediately during development/testing.