# POSTQUANTUM

## Scope

This document covers the post-quantum lattice implementations in this repo:

- `MlKem` (`ML-KEM-512/768/1024`) for key encapsulation
- `MlDsa` (`ML-DSA-44/65/87`) for signatures

The implementations are pure Rust in-tree arithmetic (no C/FFI in production paths),
with differential testing against vendored reference code.

## Foundations

This code sits on the worst-case/average-case lattice line of work started by:

- Miklos Ajtai (1996): worst-case to average-case reductions for lattice problems
- Ajtai and Dwork (1997): one of the first lattice-based public-key cryptosystems

That lineage is the conceptual backbone for modern constructions such as
module-LWE and module-SIS used by ML-KEM and ML-DSA.

## What Is Implemented

### ML-KEM (FIPS 203)

- Parameter sets: 512, 768, 1024
- APIs:
  - `MlKem::keygen`, `MlKem::keygen_from_seed`
  - `MlKem::encaps`, `MlKem::encaps_with_randomness`
  - `MlKem::decaps`
- Types:
  - `MlKemPublicKey`, `MlKemPrivateKey`, `MlKemCiphertext`, `MlKemSharedSecret`

### ML-DSA (FIPS 204)

- Parameter sets: 44, 65, 87
- APIs:
  - `MlDsa::keygen`, `MlDsa::keygen_from_seed`
  - `MlDsa::sign`, `MlDsa::sign_with_randomness`,
    `MlDsa::sign_with_randomness_and_context`
  - `MlDsa::verify`, `MlDsa::verify_with_context`
- Types:
  - `MlDsaPublicKey`, `MlDsaPrivateKey`, `MlDsaSignature`

## Why This Design

- **In-tree arithmetic**: keeps the math auditable and lets us tune performance
  directly in Rust.
- **Strict wire parsing**: malformed encodings should fail at parse time rather
  than leak into later call sites.
- **Deterministic test entry points**: explicit seed/randomness APIs are present
  for KATs, differential tests, and reproducible benchmarking.
- **`cryptography::vt` namespace**: side-channel characteristics are explicit at
  import sites.

## Serialization

Both PQ schemes separate compact payloads from self-describing blobs:

- compact: `to_wire_bytes` / `from_wire_bytes`
- self-describing: `to_key_blob` / `from_key_blob`

This keeps wire-format usage explicit while preserving one portable crate-native
blob format for storage and fixtures.

## Benchmarks

Measured with [pilot-bench](https://github.com/ascar-io/pilot-bench) via:

```text
bash scripts/bench_all_pk_full.sh
```

Numbers below are `ms/op`, with 95% CI half-width and rounds run.

- Apple M1 Max (`wigner.local`)
- Intel Xeon 6740E (`ssh.soe.ucsc.edu`, single-core slice)

### ML-KEM (Kyber)

| Operation | M1 Max ms/op | M1 Max ±CI | M1 Max Runs | Xeon 6740E ms/op | Xeon 6740E ±CI | Xeon 6740E Runs |
|---|---:|---:|---:|---:|---:|---:|
| mlkem512_keygen | 0.01947 | ±2.831e-05 | 90 | 0.02968 | ±9.867e-05 | 31 |
| mlkem512_encaps | 0.01937 | ±0.0001085 | 61 | 0.03102 | ±0.0001033 | 60 |
| mlkem512_decaps | 0.01935 | ±5.455e-05 | 137 | 0.03489 | ±0.0002393 | 60 |
| mlkem768_keygen | 0.03204 | ±4.69e-05 | 74 | 0.04913 | ±0.000296 | 30 |
| mlkem768_encaps | 0.03123 | ±3.038e-05 | 162 | 0.05036 | ±0.001314 | 30 |
| mlkem768_decaps | 0.03189 | ±0.000216 | 150 | 0.05708 | ±0.003447 | 40 |
| mlkem1024_keygen | 0.05098 | ±0.0001014 | 240 | 0.07745 | ±0.0002653 | 30 |
| mlkem1024_encaps | 0.04864 | ±4.308e-05 | 120 | 0.07629 | ±0.0002343 | 30 |
| mlkem1024_decaps | 0.04946 | ±5.068e-05 | 30 | 0.08396 | ±0.0001918 | 30 |

### ML-DSA (Dilithium)

| Operation | M1 Max ms/op | M1 Max ±CI | M1 Max Runs | Xeon 6740E ms/op | Xeon 6740E ±CI | Xeon 6740E Runs |
|---|---:|---:|---:|---:|---:|---:|
| mldsa44_keygen | 0.07784 | ±0.002088 | 60 | 0.1142 | ±0.0002587 | 60 |
| mldsa44_sign | 0.2071 | ±0.0006633 | 350 | 0.4592 | ±0.0006615 | 41 |
| mldsa44_verify | 0.07184 | ±0.000123 | 152 | 0.119 | ±0.00325 | 30 |
| mldsa65_keygen | 0.1379 | ±0.0002734 | 157 | 0.2068 | ±0.001588 | 30 |
| mldsa65_sign | 0.3587 | ±0.05607 | 30 | 0.7465 | ±0.001896 | 37 |
| mldsa65_verify | 0.1214 | ±0.001442 | 181 | 0.1893 | ±0.000978 | 30 |
| mldsa87_keygen | 0.2101 | ±0.0001558 | 65 | 0.3138 | ±0.009709 | 30 |
| mldsa87_sign | 0.4731 | ±0.001884 | 156 | 1.019 | ±0.00348 | 30 |
| mldsa87_verify | 0.207 | ±0.0003116 | 151 | 0.3107 | ±0.001124 | 40 |

## Benchmark Discussion

- `ML-KEM` scales roughly with parameter size and is stable across runs; CIs are
  tight on both hosts.
- `ML-DSA` verify is consistently cheaper than sign at each level, as expected.
- `ML-DSA` signing variance is driven by rejection behavior in the signer loop;
  this is visible in the wider CI for `mldsa65_sign` on M1.

Reference baselines (vendored C code) are available through:

- `scripts/bench_mlkem_ref.sh`
- `scripts/bench_mldsa_ref.sh`

These are for cross-checking and performance calibration, not for production
integration.

## Validation

- Full crate tests (`cargo test`) include ML-KEM and ML-DSA roundtrip/tamper
  checks.
- Differential tests compare against first-vector outputs from vendored
  reference implementations.

## References

- Ajtai, M. (1996). "Generating hard instances of lattice problems."
- Ajtai, M., and Dwork, C. (1997). "A public-key cryptosystem with worst-case/average-case equivalence."
- FIPS 203 (ML-KEM): `pubs/fips203-ml-kem.pdf`
- FIPS 204 (ML-DSA): `pubs/fips204-ml-dsa.pdf`
- Vendored reference code: `third_party/ml-dsa/dilithium-ref`,
  `third_party/ml-kem/kyber-ref`
