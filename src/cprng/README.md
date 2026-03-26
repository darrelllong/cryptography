# cprng

Cryptographic pseudorandom number generators and deterministic random bit
generators (DRBGs).

## Implemented

| File | Algorithm | Standard |
|------|-----------|----------|
| `ctr_drbg.rs` | CTR_DRBG with AES-256 | NIST SP 800-90A Rev. 1 |

## Important: seeding

`CtrDrbgAes256` is **deterministic** once seeded.  It is not an OS entropy
source — it cannot generate its own seed.  Callers must supply
cryptographically strong external seed material obtained from the operating
system:

| Platform | API |
|----------|-----|
| Linux / FreeBSD | `getrandom(2)` or `/dev/urandom` |
| macOS / iOS | `SecRandomCopyBytes` or `getentropy(2)` |
| Windows | `BCryptGenRandom` |
| Portable Rust | `getrandom` crate |

The DRBG is appropriate for:
- Deterministic key derivation when given a well-seeded initial value
- Expanding a short secret into a long keystream
- Testing and simulation with a fixed seed

It is **not** appropriate as a drop-in replacement for `rand::thread_rng()` or
any context where the caller cannot guarantee the quality of the seed.
