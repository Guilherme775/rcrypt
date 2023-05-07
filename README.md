# `mini-rcrypt`: A minimal Rust implementation of OpenBSD Blowfish password hashing code.

## Usage

```rust
use mini_rcrypt::BCrypt;

let salt = BCrypt::gensalt(5).unwrap();
let hash = BCrypt::hashpw("test".to_owned(), salt).unwrap();
let check = BCrypt::checkpw("test".to_owned(), hash);

assert!(check);
```
