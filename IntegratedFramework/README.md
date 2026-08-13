# hybrid-pqc

A working demo of **hybrid classical + post-quantum cryptography**: combining ECC
(X25519, Ed25519) with the post-quantum algorithms Kyber and Dilithium. This is the same
strategy NIST, IETF/TLS, and major browsers/CDNs use during the migration to
post-quantum cryptography — never rely on the new PQ algorithms alone until they've had
years of cryptanalysis, and never drop ECC alone now that large-scale quantum computers
are a credible future threat. Combine them so an attacker has to break *both*.

## Why "integrate", not "replace"

Kyber and Dilithium are recent (2022-2024) NIST-standardized algorithms. ECC (X25519 /
Ed25519 / ECDSA) has ~20 years of cryptanalysis behind it but is broken by a sufficiently
large quantum computer (Shor's algorithm). Neither is safe to trust alone right now:

| | Classical computer | Quantum computer |
|---|---|---|
| ECC only | secure | **broken** |
| Kyber/Dilithium only | secure (assuming no future classical break) | secure |
| **Hybrid (this repo)** | secure unless *both* break | secure unless *both* break |

A hybrid scheme is secure as long as **at least one** of the two components remains
unbroken. That's the entire design goal below.

## What's implemented

### 1. Hybrid key exchange — `src/hybrid_kem.rs`
X25519 (ECDH) + Kyber768 (KEM), combined with a **concatenation combiner**:

```
session_key = HKDF-SHA384(
    salt = transcript hash (all public keys + ciphertext),
    ikm  = Kyber_shared_secret || X25519_shared_secret,
    info = "hybrid-kem/x25519+kyber768/v1"
)
```

This is provably IND-CCA secure as long as either Kyber768 or X25519 is secure and HKDF
behaves as a PRF (Giacon/Heuer/Poettering 2018; Bindel et al. 2019) — it's the same
combiner shape as the `X25519Kyber768` hybrid key exchange used in TLS 1.3
implementations today. The transcript binding stops an attacker from mixing-and-matching
public keys/ciphertexts from different sessions.

### 2. Hybrid signatures — `src/hybrid_sig.rs`
Ed25519 + Dilithium3, combined with a **strong (AND) combiner**: a signature is only
accepted if *both* component signatures verify over the message. Forging a hybrid
signature requires breaking both Ed25519 and Dilithium3. This mirrors the approach in the
IETF LAMPS "composite signatures" draft.

### 3. Demo — `src/main.rs`
Simulates Alice and Bob: Bob publishes a hybrid KEM public key, Alice encapsulates a
session key against it, Bob decapsulates and the two keys are shown to match. Bob then
hybrid-signs that session key and the demo verifies it, then flips a bit in the message
to show verification correctly fails.

## Building and running

```
cargo run
```

### One-time Windows setup note

This machine had no Rust toolchain or C linker installed. This session:
1. Installed Rust via `rustup` (`stable-x86_64-pc-windows-gnu` toolchain — the MSVC
   toolchain's installer failed here because it needs administrator rights).
2. Installed a portable MinGW-w64 toolchain (from
   [winlibs.com](https://winlibs.com), no admin required) to
   `%USERPROFILE%\mingw64-extract\mingw64` to provide `gcc.exe`/`dlltool.exe`, since
   `pqcrypto-kyber`/`pqcrypto-dilithium` compile C reference implementations at build
   time.
3. Added that MinGW `bin` directory to your **user** `PATH`, and set
   `CC_x86_64_pc_windows_gnu` so Cargo/`cc-rs` find it automatically, and pinned the
   linker/dlltool paths in `.cargo/config.toml` as a backup.

**If `cargo build` ever fails with `gcc.exe not found` or `dlltool.exe not found`,**
open a brand-new terminal window first — Windows only picks up the PATH change in
terminals started after it was set.

## Dependencies

| Crate | Role |
|---|---|
| `pqcrypto-kyber` | Kyber768 KEM |
| `pqcrypto-dilithium` | Dilithium3 signatures |
| `x25519-dalek` | X25519 ECDH |
| `ed25519-dalek` | Ed25519 signatures |
| `hkdf` + `sha2` | KEM combiner (HKDF-SHA384) |

## Extending this into a real protocol

This repo demonstrates the cryptographic *primitives* correctly combined. To turn it
into a real secure-channel protocol you'd still need to add, at minimum: replay
protection (nonces/sequence numbers), a framing/record layer, AEAD encryption of
application data under the derived `session_key` (e.g. `AES-256-GCM` or
`ChaCha20-Poly1305`), and key rotation. Consider whether an existing hybrid-PQ TLS
implementation (e.g. OpenSSL 3.2+, BoringSSL) already meets your actual need before
building a custom protocol.
