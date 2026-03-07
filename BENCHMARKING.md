# Benchmarking

Two paths are available: a quick Rust-only path using Criterion, and a
statistically rigorous path using [pilot-bench](https://github.com/darrelllong/pilot-bench).

---

## Quick path — Criterion

No external tools required.

### Symmetric ciphers

```bash
cargo bench --manifest-path benchmarks/Cargo.toml
```

This runs `cipher_bench` (all block and stream ciphers) and `aes_bench`
(focused AES comparisons) under Criterion and opens an HTML report in
`benchmarks/target/criterion/`.

### Public-key latency (ad hoc)

```bash
cargo run --release --bin bench_public_key -- 1024
cargo run --release --bin bench_public_key -- 2048
```

Prints a table of keygen / encrypt / sign / verify latencies for every
implemented scheme at the chosen key size.

---

## Rigorous path — pilot-bench

[pilot-bench](https://github.com/darrelllong/pilot-bench) drives the
benchmark binary repeatedly until a target confidence interval is reached,
while correcting for autocorrelation and startup transients.  This is the
preferred path for numbers that go into the documentation.

### Step 1 — build pilot-bench (one-time)

Prerequisites: `cmake` ≥ 3.14, `boost` ≥ 1.74, a C++14-capable compiler.

```bash
git clone https://github.com/darrelllong/pilot-bench.git ~/pilot-bench
cd ~/pilot-bench
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_TUI=OFF ..
make -j$(nproc) bench
```

The binary lands at `~/pilot-bench/build/cli/bench` by default.
Override paths without editing scripts via:

- `PILOT_BENCH_CLI` for the pilot-bench CLI path
- `PILOT_CIPHER_BIN` for `pilot_cipher`
- `PILOT_PK_BIN` for `pilot_pk`

### Step 2 — build the Rust workload binaries

```bash
cargo build --release --bin pilot_cipher --bin pilot_pk
```

`pilot_cipher <name>` encrypts 1 MiB with the named cipher and prints
MB/s.  `pilot_pk <operation>` runs the named public-key operation N times
and prints ms/op.  Both binaries accept a single argument so pilot-bench
can drive them with `run_program`.

### Step 3 — run the suites

```bash
bash scripts/bench_all.sh        # all symmetric ciphers — throughput (MB/s)
bash scripts/bench_all_pk.sh     # EC / Edwards operations — latency (ms/op)
```

Each script emits Markdown tables ready to paste into the docs.
The `±CI` column is the 95% confidence-interval half-width reported by
pilot-bench.

---

## Supported operations

### `pilot_cipher` — symmetric throughput

| Family | Names |
|--------|-------|
| AES | `aes128`, `aes192`, `aes256` (append `ct` for constant-time) |
| Camellia | `camellia128`, `camellia192`, `camellia256` (+ `ct`) |
| CAST-128 | `cast128` (+ `ct`) |
| DES / 3DES | `des` (+ `ct`), `3des` |
| Grasshopper | `grasshopper` (+ `ct`) |
| Magma | `magma` (+ `ct`) |
| PRESENT | `present80`, `present128` (+ `ct`) |
| SEED | `seed` (+ `ct`) |
| Serpent | `serpent128`, `serpent192`, `serpent256` (+ `ct`) |
| Simon | `simon32_64` … `simon128_256` |
| SM4 | `sm4` (+ `ct`) |
| Speck | `speck32_64` … `speck128_256` |
| Twofish | `twofish128`, `twofish192`, `twofish256` (+ `ct`) |
| Stream | `chacha20`, `xchacha20`, `salsa20`, `rabbit`, `snow3g` (+ `ct`), `zuc128` (+ `ct`) |

### `pilot_pk` — public-key latency

| Family | Operations |
|--------|-----------|
| ECDSA (P-256) | `ecdsa_keygen`, `ecdsa_sign`, `ecdsa_verify` |
| ECDH (P-256) | `ecdh_keygen`, `ecdh_agree`, `ecdh_serialize` |
| ECIES (P-256) | `ecies_keygen`, `ecies_encrypt`, `ecies_decrypt` |
| EC ElGamal (P-256) | `ec_elgamal_keygen`, `ec_elgamal_encrypt`, `ec_elgamal_decrypt` |
| Ed25519 | `ed25519_keygen`, `ed25519_sign`, `ed25519_verify` |
| Edwards DH | `edwards_dh_keygen`, `edwards_dh_agree`, `edwards_dh_serialize` |
| Edwards ElGamal | `edwards_elgamal_keygen`, `edwards_elgamal_encrypt`, `edwards_elgamal_decrypt` |
| DSA 1024 | `dsa_sign_1024`, `dsa_verify_1024` |
| ElGamal 1024 | `elgamal_encrypt_1024`, `elgamal_decrypt_1024` |
| Paillier 1024 | `paillier_encrypt_1024`, `paillier_decrypt_1024` |
| RSA 1024 | `rsa_keygen_1024`, `rsa_decrypt_1024`, `rsa_sign_1024`, `rsa_verify_1024` |
| RSA 2048 | `rsa_keygen_2048`, `rsa_decrypt_2048`, `rsa_sign_2048`, `rsa_verify_2048` |

---

## Running a single operation manually

```bash
~/pilot-bench/build/cli/bench run_program --preset quick \
    --pi "ecdsa_sign,ms/op,0,1,1" \
    -- ./target/release/pilot_pk ecdsa_sign

~/pilot-bench/build/cli/bench run_program --preset quick \
    --pi "aes256,MB/s,0,1,1" \
    -- ./target/release/pilot_cipher aes256
```

`--preset quick` targets 20 % CI.  Use `--preset normal` for 10 % or
`--preset strict` for tighter bounds.
