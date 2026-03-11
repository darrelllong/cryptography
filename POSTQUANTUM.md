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

## Theory of Operation

### ML-KEM (FIPS 203)

At a high level:

1. `keygen` samples a public matrix seed and secret short vectors, then derives
   `(pk, sk)` where `sk` includes auxiliary values required for CCA security.
2. `encaps` samples ephemeral randomness, derives `(ciphertext, shared_secret)`
   against a recipient `pk`.
3. `decaps` recomputes and validates the encapsulation relation and returns the
   same `shared_secret` as the encapsulator (or an implicit-rejection value for
   malformed ciphertexts).

Operationally, treat the returned shared secret as KDF input, not as a final
application key.

### ML-DSA (FIPS 204)

At a high level:

1. `keygen` expands a deterministic seed into matrix and short vectors, then
   packs `(pk, sk)` with the hash/transcript material required by verification.
2. `sign` computes a Fiat-Shamir challenge over message transcript data and
   uses rejection sampling until the signature bounds are satisfied.
3. `verify` reconstructs the challenge transcript from `(pk, message,
   signature)` and accepts iff it matches.

The optional context is part of the signed transcript and must match exactly at
verification time.

## Working Examples

These examples are executable and mirrored by
`tests/manual_examples.rs::manual_postquantum_examples`.

### ML-KEM end-to-end + wire/blob roundtrips

```rust
use cryptography::vt::{
    MlKem, MlKemParameterSet, MlKemPrivateKey, MlKemPublicKey,
};
use cryptography::CtrDrbgAes256;

let mut rng = CtrDrbgAes256::new(&[0x11u8; 48]);

let (pk, sk) = MlKem::keygen(MlKemParameterSet::MlKem768, &mut rng).expect("keygen");
let (ct, ss_sender) = MlKem::encaps(&pk, &mut rng).expect("encaps");
let ss_receiver = MlKem::decaps(&sk, &ct).expect("decaps");
assert_eq!(ss_sender.to_wire_bytes(), ss_receiver.to_wire_bytes());

let pk_wire = pk.to_wire_bytes();
let pk_round = MlKemPublicKey::from_wire_bytes(MlKemParameterSet::MlKem768, &pk_wire).expect("pk");
assert_eq!(pk_round, pk);

let sk_blob = sk.to_key_blob();
let sk_round = MlKemPrivateKey::from_key_blob(&sk_blob).expect("sk");
assert_eq!(sk_round, sk);
```

### ML-DSA sign/verify + context + signature wire roundtrip

```rust
use cryptography::vt::{
    MlDsa, MlDsaParameterSet, MlDsaSignature,
};
use cryptography::CtrDrbgAes256;

let mut rng = CtrDrbgAes256::new(&[0x22u8; 48]);
let (pk, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa65, &mut rng).expect("keygen");

let sig = MlDsa::sign(&sk, b"release manifest", &mut rng).expect("sign");
assert!(MlDsa::verify(&pk, b"release manifest", &sig));
assert!(!MlDsa::verify(&pk, b"tampered", &sig));

let ctx = b"bundle:v1";
let rnd = [0x5Cu8; 32];
let sig_ctx = MlDsa::sign_with_randomness_and_context(&sk, b"payload", &rnd, ctx).expect("sign");
assert!(MlDsa::verify_with_context(&pk, b"payload", &sig_ctx, ctx));
assert!(!MlDsa::verify_with_context(&pk, b"payload", &sig_ctx, b"bundle:v2"));

let sig_wire = sig.to_wire_bytes();
let sig_round =
    MlDsaSignature::from_wire_bytes(MlDsaParameterSet::MlDsa65, &sig_wire).expect("sig");
assert!(MlDsa::verify(&pk, b"release manifest", &sig_round));
```

## Benchmarks

Measured with [pilot-bench](https://github.com/ascar-io/pilot-bench) via:

```text
bash scripts/bench_all_pk_full.sh
```

Numbers below are `ms/op`, with 95% CI half-width and rounds run.

- Apple M1 Max (`wigner.local`)
- Intel Xeon 6740E (`ssh.soe.ucsc.edu`, single-core slice)

### ML-KEM (Kyber)

| Operation | M1 Max ms/op | M1 Max ± CI | M1 Max Runs | Xeon 6740E ms/op | Xeon 6740E ± CI | Xeon 6740E Runs |
|---|---:|---:|---:|---:|---:|---:|
| mlkem512_keygen | 0.01947 | $\pm$2.831e-05 | 90 | 0.02968 | $\pm$9.867e-05 | 31 |
| mlkem512_encaps | 0.01937 | $\pm$0.0001085 | 61 | 0.03102 | $\pm$0.0001033 | 60 |
| mlkem512_decaps | 0.01935 | $\pm$5.455e-05 | 137 | 0.03489 | $\pm$0.0002393 | 60 |
| mlkem768_keygen | 0.03204 | $\pm$4.69e-05 | 74 | 0.04913 | $\pm$0.000296 | 30 |
| mlkem768_encaps | 0.03123 | $\pm$3.038e-05 | 162 | 0.05036 | $\pm$0.001314 | 30 |
| mlkem768_decaps | 0.03189 | $\pm$0.000216 | 150 | 0.05708 | $\pm$0.003447 | 40 |
| mlkem1024_keygen | 0.05098 | $\pm$0.0001014 | 240 | 0.07745 | $\pm$0.0002653 | 30 |
| mlkem1024_encaps | 0.04864 | $\pm$4.308e-05 | 120 | 0.07629 | $\pm$0.0002343 | 30 |
| mlkem1024_decaps | 0.04946 | $\pm$5.068e-05 | 30 | 0.08396 | $\pm$0.0001918 | 30 |

### ML-DSA (Dilithium)

| Operation | M1 Max ms/op | M1 Max ± CI | M1 Max Runs | Xeon 6740E ms/op | Xeon 6740E ± CI | Xeon 6740E Runs |
|---|---:|---:|---:|---:|---:|---:|
| mldsa44_keygen | 0.07784 | $\pm$0.002088 | 60 | 0.1142 | $\pm$0.0002587 | 60 |
| mldsa44_sign | 0.2071 | $\pm$0.0006633 | 350 | 0.4592 | $\pm$0.0006615 | 41 |
| mldsa44_verify | 0.07184 | $\pm$0.000123 | 152 | 0.119 | $\pm$0.00325 | 30 |
| mldsa65_keygen | 0.1379 | $\pm$0.0002734 | 157 | 0.2068 | $\pm$0.001588 | 30 |
| mldsa65_sign | 0.3587 | $\pm$0.05607 | 30 | 0.7465 | $\pm$0.001896 | 37 |
| mldsa65_verify | 0.1214 | $\pm$0.001442 | 181 | 0.1893 | $\pm$0.000978 | 30 |
| mldsa87_keygen | 0.2101 | $\pm$0.0001558 | 65 | 0.3138 | $\pm$0.009709 | 30 |
| mldsa87_sign | 0.4731 | $\pm$0.001884 | 156 | 1.019 | $\pm$0.00348 | 30 |
| mldsa87_verify | 0.207 | $\pm$0.0003116 | 151 | 0.3107 | $\pm$0.001124 | 40 |

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

Primary standards PDFs are stored in `pubs/`. The canonical BibTeX entries are
in [README.md](README.md).

- Miklos Ajtai, "Generating Hard Instances of Lattice Problems (Extended
  Abstract)," *Proceedings of the Twenty-Eighth Annual ACM Symposium on Theory
  of Computing (STOC '96)*, pp. 99-108, 1996.
  DOI: [10.1145/237814.237838](https://doi.org/10.1145/237814.237838)
- Miklos Ajtai and Cynthia Dwork, "A Public-Key Cryptosystem with
  Worst-Case/Average-Case Equivalence," *Proceedings of the Twenty-Ninth
  Annual ACM Symposium on Theory of Computing (STOC '97)*, pp. 284-293, 1997.
  DOI: [10.1145/258533.258604](https://doi.org/10.1145/258533.258604)
- National Institute of Standards and Technology, *Module-Lattice-Based
  Key-Encapsulation Mechanism Standard (FIPS 203)*, 2024.
  DOI: [10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
  (local copy: `pubs/fips203-ml-kem.pdf`)
- National Institute of Standards and Technology, *Module-Lattice-Based Digital
  Signature Standard (FIPS 204)*, 2024.
  DOI: [10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
  (local copy: `pubs/fips204-ml-dsa.pdf`)
- Vendored reference code (for differential testing/benchmark calibration):
  `third_party/ml-kem/kyber-ref`, `third_party/ml-dsa/dilithium-ref`
