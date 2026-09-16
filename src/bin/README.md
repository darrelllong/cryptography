# bin

Binary utilities for benchmarking, piloting, and statistical testing.

These are not part of the library API.  They exist to exercise the library
from the outside, produce benchmark data, and sanity-check implementations
interactively.

| File | Purpose |
|------|---------|
| `bench_public_key.rs` | One-shot latency (ms/op) for every public-key scheme in `cryptography::vt`; takes the modulus size and optional `--skip-*` flags |
| `cipher_encrypt.rs` | Driver for the R randomness battery (`scripts/cipher_randomness.R`): `cipher_encrypt <name> < plaintext > ciphertext` encrypts stdin under one of the battery's 34 cipher names — block ciphers in CTR mode, stream ciphers in native keystream mode — with a fresh `/dev/urandom` key and IV that are never emitted; statistical use only. No or an unknown name lists the names on stderr and exits 2 |
| `pilot_cipher.rs` | Throughput driver for symmetric ciphers (`pilot_cipher <name>` prints MB/s); driven by `pilot-bench` via `scripts/bench_all.sh` |
| `pilot_hash.rs` | Throughput driver for hashes and XOFs (`pilot_hash <name>` prints MB/s); driven by `scripts/bench_all_hash.sh` |
| `pilot_pk.rs` | Latency driver for public-key operations (`pilot_pk <operation>` prints ms/op); driven by `scripts/bench_all_pk*.sh` |
| `pilot_sm4.rs` | Minimal SM4 ECB throughput driver kept as a smoke check for the table-driven path |
| `profile_ct_anf.rs` | Profiles constant-time ANF S-box helper activity per cipher (build with `--features ct_profile`) |

## Running

```sh
# Run a specific binary
cargo run --release --bin pilot_cipher -- aes128

# Public-key latency table
cargo run --release --bin bench_public_key -- 2048
```

Benchmark output is tab- or pipe-separated and intended to be pasted into
`../../BENCHMARKING.md`, `../../SYMMETRIC.md`, or `../../ASYMMETRIC.md`; the
Pilot workflow that produces the published numbers is described in
`../../BENCHMARKING.md`.
