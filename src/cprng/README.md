# cprng

Cryptographic pseudorandom number generators and deterministic random bit
generators (DRBGs).

## Implemented

| File | Algorithm | Standard |
|------|-----------|----------|
| `ctr_drbg.rs` | CTR_DRBG with AES-256, no derivation function | NIST SP 800-90A Rev. 1 §10.2.1 |

`CtrDrbg<C>` is generic over the AES-256 implementation. `CtrDrbgAes256`
(= `CtrDrbg<Aes256>`) runs on the T-table AES and is variable-time: the table
indices are the DRBG's key and counter. `CtrDrbgAes256Ct` (= `CtrDrbg<Aes256Ct>`)
runs on the Boyar–Peralta circuit AES and has no secret-dependent memory
access. The two agree bit for bit; the NIST DRBGVS vectors in
`tests/kat_ctr_drbg.rs` run through both. The DRBG keys an encrypt-only
schedule, since `CTR_DRBG` never decrypts.

What is implemented is the §10.2.1 mechanism only: instantiate, reseed,
generate (additional input up to `seedlen`, zero-padded), and wipe on drop. No
entropy source, no prediction resistance, no health tests, no derivation
function: the caller supplies 48 bytes of conditioned seed material to `new`
and `reseed`, formed as SP 800-90A §10.2.1.3.1 / §10.2.1.4.1 steps 1–3 form it.

This module is intentionally narrow.  `cryptography` provides only the
CSPRNG primitive here; the sibling [`entropy`](https://github.com/darrelllong/entropy)
repository depends on this crate and supplies a much broader collection of
generators — stream-cipher RNGs, non-cryptographic generators (LCG, MT19937,
PCG, xoshiro, …), and the full statistical test batteries (NIST SP 800-22,
DIEHARD, DIEHARDER) that evaluate them.

## Important: seeding

`CtrDrbgAes256` and `CtrDrbgAes256Ct` are **deterministic** once seeded.  It is not an OS entropy
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
