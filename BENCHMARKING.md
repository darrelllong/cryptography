# Benchmarking

All publication-facing benchmarks are Pilot-driven via
[pilot-bench](https://github.com/darrelllong/pilot-bench).  
There is no separate Criterion path in this workflow.

---

## Pilot Path

[pilot-bench](https://github.com/darrelllong/pilot-bench) drives the
benchmark binary repeatedly until a target confidence interval is reached,
while correcting for autocorrelation and startup transients.  This is the
preferred path for numbers that go into the documentation.

### Step 1 — build pilot-bench (one-time)

Prerequisites: `cmake` $\ge$ 3.14, `boost` $\ge$ 1.74, a C++14-capable compiler.

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
- `PILOT_HASH_BIN` for `pilot_hash`
- `PILOT_PK_BIN` for `pilot_pk`

Tune run behavior without editing scripts via:

- `PILOT_PRESET` (`quick`, `normal`, `strict`; default `quick`)
- `PILOT_CONFIDENCE_LEVEL` (e.g. `0.90` for 90%; default unset, which leaves pilot-bench's 0.95 in place)
- `PILOT_CIPHER_BYTES` (bytes per `pilot_cipher` invocation; default `262144`)
- `PILOT_HASH_BYTES` (bytes per `pilot_hash` invocation; default `262144`)
- `PILOT_HASH_XOF_OUT` (bytes squeezed per XOF round in `pilot_hash`; default `32`)
- `PILOT_PK_ITERS_PERCENT` (scales per-invocation loop counts in `pilot_pk`; default `25`)

For Apple Silicon optimization loops (no assembly, in-repo code only), use:

- [fast/Apple-Silicon/README.md](fast/Apple-Silicon/README.md)
- `bash fast/Apple-Silicon/scripts/run_hotspots_symmetric.sh`
- `bash fast/Apple-Silicon/scripts/run_hotspots_pk.sh`
- `bash fast/Apple-Silicon/scripts/profile_ct_anf.sh`

For x86 optimization loops (no assembly, in-repo code only), use:

- [fast/x86/README.md](fast/x86/README.md)
- `bash fast/x86/scripts/run_alt_suite.sh`

Promotion gate for published go-fast kernels is $\ge 5\times$ over baseline/reference.
Lower-speedup comparator results are tracked as exploratory only.

Use the split scripts so unchanged PK or symmetric areas are not re-run.
The baseline `src/` tree remains the pure safe Rust reference; Apple-Silicon
acceleration work is maintained as an explicit alternative path.

### Step 2 — build the Rust workload binaries

```bash
cargo build --release --bin pilot_cipher --bin pilot_hash --bin pilot_pk
```

`pilot_cipher <name>` encrypts a fixed workload and prints MB/s.
`pilot_hash <name>` absorbs a fixed workload (and squeezes a fixed number
of bytes for XOFs) and prints MB/s.
`pilot_pk <operation>` runs the named public-key operation N times
and prints ms/op. All three binaries accept a single argument so pilot-bench
can drive them with `run_program`.

By default, `pilot_cipher` and `pilot_hash` process `262144` bytes per
invocation. Override with `PILOT_CIPHER_BYTES=<bytes>` /
`PILOT_HASH_BYTES=<bytes>` to tune per-round runtime for a host.

### Step 3 — run the suites

```bash
bash scripts/bench_all.sh        # all symmetric ciphers — throughput (MB/s)
bash scripts/bench_all_hash.sh   # all hashes / XOFs — throughput (MB/s)
bash scripts/bench_all_pk.sh     # PK subset (EC/Edwards/PQ) — latency (ms/op)
bash scripts/bench_all_pk_full.sh  # full PK suite (finite-field + EC + Edwards + PQ)
```

Each script emits Markdown tables ready to paste into the docs.
The `± CI` column is the confidence-interval half-width reported by
pilot-bench. By default it is **95%**; export `PILOT_CONFIDENCE_LEVEL=0.90`
(or any value in `(0,1)`) before invoking the script to request a
different level.

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

### `pilot_hash` — hash / XOF throughput

| Family | Names |
|--------|-------|
| Legacy | `md5`, `sha1`, `ripemd160` |
| SHA-2 | `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256` |
| SHA-3 | `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512` |
| SHAKE XOFs | `shake128`, `shake256` (squeeze `PILOT_HASH_XOF_OUT` bytes per round) |

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
| X25519 (RFC 7748) | `x25519_keygen`, `x25519_agree`, `x25519_scalar_mult_base`, `x25519_scalar_mult` |
| X448 (RFC 7748) | `x448_keygen`, `x448_agree`, `x448_scalar_mult_base`, `x448_scalar_mult` |
| ML-KEM | `mlkem512_keygen`, `mlkem512_encaps`, `mlkem512_decaps`, `mlkem768_keygen`, `mlkem768_encaps`, `mlkem768_decaps`, `mlkem1024_keygen`, `mlkem1024_encaps`, `mlkem1024_decaps` |
| ML-DSA | `mldsa44_keygen`, `mldsa44_sign`, `mldsa44_verify`, `mldsa65_keygen`, `mldsa65_sign`, `mldsa65_verify`, `mldsa87_keygen`, `mldsa87_sign`, `mldsa87_verify` |
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

For Pilot-driven reference-C baselines from the vendored Kyber code, run:

```bash
bash scripts/bench_mlkem_ref.sh
```

For Pilot-driven reference-C baselines from the vendored Dilithium code, run:

```bash
bash scripts/bench_mldsa_ref.sh
```

---

## Bigint kernels vs GMP

The bigint microbenchmark and its GMP mirror moved with the multiprecision
layer to the [rump](https://github.com/darrelllong/rump) crate:

```bash
cd ../rump
cargo run --release --bin bench_bigint          # ours
bash scripts/bench_gmp.sh                       # GMP, same table format
```
