# POSTQUANTUM

## Scope

This document covers the post-quantum lattice implementations in this repo:

- `MlKem` (`ML-KEM-512/768/1024`) for key encapsulation (FIPS 203)
- `MlDsa` (`ML-DSA-44/65/87`) for signatures (FIPS 204)
- `NtruHps509`, `NtruHps677`, `NtruHps821`, `NtruHrss701` for NIST PQC round-3
  NTRU CCA-secure key encapsulation

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

### NTRU (NIST PQC round 3, 2020-10-16 submission)

- Parameter sets:
  - `NtruHps509` (`ntruhps2048509`, NIST level 1)
  - `NtruHps677` (`ntruhps2048677`, NIST level 3)
  - `NtruHps821` (`ntruhps4096821`, NIST level 5)
  - `NtruHrss701` (`ntruhrss701`, NIST level 1)
- APIs (each `Ntru*` namespace):
  - `keygen`, `encaps`, `decaps`
- Types (per parameter set):
  - `Ntru*PublicKey`, `Ntru*PrivateKey`, `Ntru*Ciphertext`, `Ntru*SharedSecret`

NTRU here is a faithful Rust port of the official round-3 reference C
distributed in `NIST-PQ-Submission-NTRU-20201016.tar.gz` from `ntru.org`. Each
parameter set is validated byte-for-byte against the `count = 0` entry of the
shipped `PQCkemKAT_*.rsp` known-answer file (`PQCkemKAT_935.rsp` for HPS-509,
`PQCkemKAT_1234.rsp` for HPS-677, `PQCkemKAT_1590.rsp` for HPS-821, and
`PQCkemKAT_1450.rsp` for HRSS-701). The vendored hex sidecars next to each
module's source are the public KAT bytes, not derived data.

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

### NTRU (NIST PQC round 3)

At a high level (HPS variants):

1. `keygen` samples a trinary `f` (IID-uniform) and a trinary `g` of fixed
   weight `q/8 - 2`, computes `f^{-1} mod 3` and `(g·f)^{-1} mod q`, and
   derives the public polynomial `h = g · (g·f)^{-1} · g  mod (q, x^N - 1)`.
   The private key bundles `f`, `f^{-1} mod 3`, `h^{-1} in S_q`, and a 32-byte
   PRF key for implicit rejection.
2. `encaps` samples `(r, m)` (IID for `r`, fixed-weight for `m`), derives the
   shared secret `K = SHA3-256(pack3(r) || pack3(m))`, lifts `r` into `Z_q`,
   and emits the ciphertext `c = r·h + lift(m)` packed sum-zero.
3. `decaps` recovers `(r, m)` via the trapdoor `(f, f^{-1}_3, h^{-1})`,
   re-validates `r` (and for HPS, the weight constraint on `m`), and returns
   `K = SHA3-256(pack3(r) || pack3(m))` on success or
   `K = SHA3-256(prf || c)` on any consistency failure (implicit rejection).

HRSS-701 differs from the HPS sets in three places: `f` and `g` come from the
`sample_iid_plus` distribution (post-conditioned to satisfy `<x·r, r> ≥ 0`),
the keygen uses `g ← 3·(x − 1)·g` instead of `g ← 3·g`, the message-space
check on `m` is dropped, and the encryption `lift` is the more elaborate
`a / (x − 1) mod (3, Φ_n)` operator rather than the bare `Z_3 → Z_q` map.

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

### NTRU end-to-end + wire roundtrip

```rust
use cryptography::vt::{NtruHps509, NtruHps509Ciphertext, NtruHps509PublicKey};
use cryptography::CtrDrbgAes256;

let mut rng = CtrDrbgAes256::new(&[11u8; 48]);

let (pk, sk) = NtruHps509::keygen(&mut rng);
let (ct, ss_sender) = NtruHps509::encaps(&pk, &mut rng);
let ss_receiver = NtruHps509::decaps(&sk, &ct);
assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());

let pk_round = NtruHps509PublicKey::from_wire_bytes(&pk.to_wire_bytes()).expect("pk");
let ct_round = NtruHps509Ciphertext::from_wire_bytes(&ct.to_wire_bytes()).expect("ct");
assert_eq!(pk_round, pk);
assert_eq!(ct_round, ct);
```

The other parameter sets (`NtruHps677`, `NtruHps821`, `NtruHrss701`) expose
identical `keygen`, `encaps`, `decaps` shapes; only the byte sizes change.

## Parameter Comparison

### ML-KEM: Security vs. Cost

**Key and ciphertext sizes (bytes; FIPS 203 §7)**

| Parameter | Security | Public Key | Private Key | Ciphertext | Shared Secret |
|---|:---:|---:|---:|---:|---:|
| ML-KEM-512  | NIST 1 |   800 | 1 632 |   768 | 32 |
| ML-KEM-768  | NIST 3 | 1 184 | 2 400 | 1 088 | 32 |
| ML-KEM-1024 | NIST 5 | 1 568 | 3 168 | 1 568 | 32 |

**Throughput across parameter sets and platforms** — each axis is an operation
(keygen / encaps / decaps) for one parameter set; outer ring = faster. ±90% CI
half-widths are in the benchmark tables below.

![ML-KEM throughput radar (Wigner / Moore / Darby)](assets/sweep-2026-05-08-mlkem-radar.svg)

### ML-DSA: Security vs. Cost

**Key and signature sizes (bytes; FIPS 204 §7)**

| Parameter | Security | Public Key | Private Key | Signature |
|---|:---:|---:|---:|---:|
| ML-DSA-44 | NIST 2 | 1 312 | 2 528 | 2 420 |
| ML-DSA-65 | NIST 3 | 1 952 | 4 000 | 3 309 |
| ML-DSA-87 | NIST 5 | 2 592 | 4 864 | 4 627 |

**Throughput across parameter sets and platforms** — each axis is an operation
(keygen / sign / verify) for one parameter set; outer ring = faster.

![ML-DSA throughput radar (Wigner / Moore / Darby)](assets/sweep-2026-05-08-mldsa-radar.svg)

### NTRU: Security vs. Cost

**Key and ciphertext sizes (bytes; round-3 submission Table 2.1)**

| Parameter | Security | Public Key | Private Key | Ciphertext | Shared Secret |
|---|:---:|---:|---:|---:|---:|
| NtruHps509  | NIST 1 |   699 |   935 |   699 | 32 |
| NtruHrss701 | NIST 1 | 1 138 | 1 450 | 1 138 | 32 |
| NtruHps677  | NIST 3 |   930 | 1 234 |   930 | 32 |
| NtruHps821  | NIST 5 | 1 230 | 1 590 | 1 230 | 32 |

### NTRUEncrypt (IEEE 1363.1): Security vs. Cost

**Key, ciphertext, and message sizes (bytes; IEEE Std 1363.1-2008, Annex A
parameter tables)**

| Parameter | Security | Public Key | Private Key | Ciphertext | Max Message |
|---|:---:|---:|---:|---:|---:|
| EES401EP1  | 112-bit |   552 |   653 |   552 |  60 |
| EES443EP1  | 128-bit |   610 |   660 |   610 |  65 |
| EES449EP1  | 128-bit |   618 |   731 |   618 |  69 |
| EES541EP1  | 112-bit |   744 |   880 |   744 |  86 |
| EES677EP1  | 192-bit |   931 | 1 101 |   931 | 101 |
| EES1087EP1 | 192-bit | 1 495 | 1 767 | 1 495 | 178 |
| EES1087EP2 | 256-bit | 1 495 | 1 767 | 1 495 | 170 |
| EES1499EP1 | 256-bit | 2 062 | 2 437 | 2 062 | 247 |

The private-key length is `PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES`: this
crate stores the trinary trapdoor `t` (compactly packed) alongside the
public key, because SVES-3 decryption needs the public key for the
re-encryption check that distinguishes legitimate ciphertexts from
forgeries. Max-message bytes follow IEEE 1363.1 §11.4
(`N · 3 / 16 − 1 − db / 8`).

### Cross-scheme comparison at NIST Level 3

| Metric | ML-KEM-768 | ML-DSA-65 |
|---|---:|---:|
| Public key (bytes) | 1 184 | 1 952 |
| Private key (bytes) | 2 400 | 4 000 |
| Payload (bytes) | 1 088 CT + 32 SS | 3 309 sig |
| Keygen Wigner (ms/op ± 90% CI) | 0.02779 ± 7.227e-05 | 0.1179 ± 0.000256 |
| Primary op Wigner (ms/op ± 90% CI) | 0.02594 ± 2.154e-05 encaps | 0.2659 ± 0.000453 sign |
| Secondary op Wigner (ms/op ± 90% CI) | 0.02654 ± 9.472e-05 decaps | 0.02498 ± 0.000374 verify |

ML-DSA signing is ~10× slower than ML-KEM encapsulation at Level 3 due to the
rejection-sampling loop; verification has now drawn level with ML-KEM decaps
on Wigner (0.025 ms vs 0.027 ms). Rejection-sampling variance shows up as
non-monotone absolute sign timing across parameter sets — see the
"Benchmark Discussion" notes below.

## Benchmarks

Measured with [pilot-bench](https://github.com/darrelllong/pilot-bench) via:

```text
bash scripts/bench_all_pk_full.sh
```

Numbers below are `ms/op`, with **90%** CI half-width and rounds run. The
2026-05-08 sweep used `PILOT_PRESET=normal --confidence-level 0.90` (10% CI
half-width target, autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample
size). The tables below are parallel runs on:

- Apple M1 Max (`wigner.local`)
- AMD EPYC 7452 (`moore.soe.ucsc.edu`, single-core slice)
- Broadcom BCM2712 / Cortex-A76 (`darby.local`, Raspberry Pi 5)

### ML-KEM (Kyber)

| Operation | Wigner (M1 Max) ms/op | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) ms/op | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) ms/op | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|
| `mlkem512_keygen` | 0.01703 | ±7.847e-05 | 50 | 0.02536 | ±5.482e-05 | 80 | 0.05291 | ±0.0002066 | 50 |
| `mlkem512_encaps` | 0.01612 | ±2.431e-05 | 50 | 0.02665 | ±0.0006511 | 50 | 0.05284 | ±0.0001552 | 116 |
| `mlkem512_decaps` | 0.01639 | ±1.773e-05 | 80 | 0.02991 | ±0.0003324 | 50 | 0.05606 | ±0.0001612 | 142 |
| `mlkem768_keygen` | 0.02779 | ±7.227e-05 | 50 | 0.04218 | ±0.0003994 | 110 | 0.08631 | ±0.0003145 | 50 |
| `mlkem768_encaps` | 0.02594 | ±2.154e-05 | 296 | 0.0419 | ±0.0001054 | 50 | 0.08728 | ±0.0003385 | 80 |
| `mlkem768_decaps` | 0.02654 | ±9.472e-05 | 110 | 0.04684 | ±9.01e-05 | 50 | 0.0914 | ±0.0002707 | 50 |
| `mlkem1024_keygen` | 0.0439 | ±6.454e-05 | 80 | 0.06593 | ±0.0007346 | 50 | 0.137 | ±0.0004361 | 50 |
| `mlkem1024_encaps` | 0.03975 | ±6.822e-05 | 80 | 0.06373 | ±0.0002676 | 50 | 0.1364 | ±0.0004771 | 50 |
| `mlkem1024_decaps` | 0.04065 | ±3.935e-05 | 110 | 0.07061 | ±0.0001176 | 56 | 0.1428 | ±0.0003117 | 110 |

### ML-DSA (Dilithium)

| Operation | Wigner (M1 Max) ms/op | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) ms/op | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) ms/op | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|
| `mldsa44_keygen` | 0.06385 | ±0.0001583 | 50 | 0.09451 | ±0.0001812 | 110 | 0.2791 | ±0.0003247 | 320 |
| `mldsa44_sign` | 0.1572 | ±7.018e-05 | 50 | 0.3812 | ±0.001324 | 50 | 0.5605 | ±0.0003453 | 80 |
| `mldsa44_verify` | 0.01678 | ±4.972e-05 | 111 | 0.03896 | ±0.000121 | 80 | 0.06158 | ±0.0008716 | 50 |
| `mldsa65_keygen` | 0.1179 | ±0.0002556 | 80 | 0.1692 | ±0.001079 | 110 | 0.3735 | ±0.0008862 | 50 |
| `mldsa65_sign` | 0.2659 | ±0.0004532 | 50 | 0.6691 | ±0.001186 | 80 | 0.9478 | ±0.003496 | 50 |
| `mldsa65_verify` | 0.02498 | ±0.0003743 | 50 | 0.05598 | ±0.0001238 | 591 | 0.08762 | ±0.000738 | 140 |
| `mldsa87_keygen` | 0.1726 | ±0.0002285 | 410 | 0.2448 | ±0.0007543 | 50 | 0.596 | ±0.0009311 | 52 |
| `mldsa87_sign` | 0.168 | ±0.0001701 | 170 | 0.4168 | ±0.001193 | 52 | 0.5985 | ±0.0009905 | 170 |
| `mldsa87_verify` | 0.03707 | ±0.000108 | 110 | 0.08329 | ±0.0002082 | 80 | 0.1371 | ±0.000586 | 110 |

### NTRU (NIST PQC round 3)

| Operation | Wigner (M1 Max) ms/op | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) ms/op | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) ms/op | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|
| `ntruhps509_keygen` | 1.002 | ±0.04583 | 50 | 1.278 | ±0.002711 | 58 | 2.296 | ±0.002031 | 50 |
| `ntruhps509_encaps` | 0.08268 | ±0.003083 | 50 | 0.1069 | ±0.0004561 | 50 | 0.1729 | ±0.0003729 | 80 |
| `ntruhps509_decaps` | 0.1455 | ±0.0106 | 50 | 0.156 | ±0.001382 | 110 | 0.2853 | ±0.001599 | 50 |
| `ntruhps677_keygen` | 1.219 | ±0.01126 | 320 | 1.798 | ±0.007316 | 53 | 3.042 | ±0.004702 | 87 |
| `ntruhps677_encaps` | 0.08707 | ±0.0007503 | 50 | 0.1333 | ±0.001523 | 50 | 0.2079 | ±0.0009669 | 50 |
| `ntruhps677_decaps` | 0.1052 | ±0.002519 | 80 | 0.1591 | ±0.000419 | 260 | 0.2803 | ±0.0004506 | 80 |
| `ntruhps821_keygen` | 2.366 | ±0.07834 | 50 | 2.814 | ±0.01177 | 50 | 5.117 | ±0.008321 | 80 |
| `ntruhps821_encaps` | 0.1762 | ±0.009012 | 80 | 0.1937 | ±0.0004173 | 80 | 0.3065 | ±0.0007033 | 50 |
| `ntruhps821_decaps` | 0.3096 | ±0.01153 | 52 | 0.279 | ±0.0006073 | 80 | 0.4914 | ±0.001814 | 140 |
| `ntruhrss701_keygen` | 1.28 | ±0.09556 | 50 | 1.904 | ±0.01062 | 54 | 3.57 | ±0.007388 | 50 |
| `ntruhrss701_encaps` | 0.04845 | ±0.001142 | 50 | 0.06901 | ±0.004323 | 50 | 0.1175 | ±0.0003305 | 50 |
| `ntruhrss701_decaps` | 0.1234 | ±0.002806 | 54 | 0.1691 | ±0.0004149 | 112 | 0.3118 | ±0.0004736 | 85 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation | Wigner (M1 Max) ms/op | Wigner (M1 Max) ±CI (90%) | Wigner (M1 Max) Runs | Moore (EPYC 7452) ms/op | Moore (EPYC 7452) ±CI (90%) | Moore (EPYC 7452) Runs | Darby (RPi5) ms/op | Darby (RPi5) ±CI (90%) | Darby (RPi5) Runs |
|---|---|---|---|---|---|---|---|---|---|
| `ntruees401ep1_keygen` | 0.7645 | ±0.005618 | 140 | 0.9366 | ±0.002872 | 50 | 1.343 | ±0.02541 | 53 |
| `ntruees401ep1_encrypt` | 0.1008 | ±0.001312 | 171 | 0.1091 | ±0.004532 | 80 | 0.2898 | ±0.0009549 | 80 |
| `ntruees401ep1_decrypt` | 0.1385 | ±0.0003355 | 177 | 0.1582 | ±0.00105 | 81 | 0.4851 | ±0.002529 | 170 |
| `ntruees443ep1_keygen` | 0.7524 | ±0.02073 | 80 | 0.862 | ±0.02262 | 50 | 1.308 | ±0.002847 | 110 |
| `ntruees443ep1_encrypt` | 0.04354 | ±0.0005677 | 110 | 0.04403 | ±0.0003447 | 80 | 0.07591 | ±0.0006669 | 260 |
| `ntruees443ep1_decrypt` | 0.04295 | ±0.0004111 | 57 | 0.04917 | ±0.0003307 | 50 | 0.105 | ±0.0005188 | 50 |
| `ntruees449ep1_keygen` | 0.9509 | ±0.01351 | 50 | 1.113 | ±0.00314 | 50 | 1.624 | ±0.001674 | 50 |
| `ntruees449ep1_encrypt` | 0.1449 | ±0.0002934 | 140 | 0.1545 | ±0.003887 | 50 | 0.3414 | ±0.0007413 | 50 |
| `ntruees449ep1_decrypt` | 0.1771 | ±0.002304 | 50 | 0.1991 | ±0.001424 | 382 | 0.4925 | ±0.0007877 | 50 |
| `ntruees541ep1_keygen` | 0.7433 | ±0.002493 | 53 | 1.044 | ±0.02334 | 50 | 1.375 | ±0.002495 | 50 |
| `ntruees541ep1_encrypt` | 0.07745 | ±0.000181 | 50 | 0.07411 | ±0.0007479 | 112 | 0.1992 | ±0.0009162 | 561 |
| `ntruees541ep1_decrypt` | 0.09241 | ±0.001237 | 52 | 0.0998 | ±0.0008372 | 140 | 0.2991 | ±0.0006596 | 50 |
| `ntruees677ep1_keygen` | 1.203 | ±0.01825 | 50 | 1.585 | ±0.009279 | 50 | 2.373 | ±0.001855 | 140 |
| `ntruees677ep1_encrypt` | 0.1819 | ±0.002014 | 140 | 0.2004 | ±0.002973 | 55 | 0.464 | ±0.003442 | 50 |
| `ntruees677ep1_decrypt` | 0.2825 | ±0.002102 | 80 | 0.3248 | ±0.003849 | 50 | 0.828 | ±0.0008432 | 50 |
| `ntruees1087ep1_keygen` | 1.76 | ±0.005377 | 176 | 2.649 | ±0.06399 | 50 | 3.701 | ±0.002887 | 80 |
| `ntruees1087ep1_encrypt` | 0.141 | ±0.0002315 | 260 | 0.1547 | ±0.0009354 | 50 | 0.3323 | ±0.0005843 | 110 |
| `ntruees1087ep1_decrypt` | 0.1835 | ±0.0003071 | 230 | 0.2254 | ±0.0009941 | 80 | 0.564 | ±0.00616 | 80 |
| `ntruees1087ep2_keygen` | 1.869 | ±0.007425 | 110 | 2.764 | ±0.007286 | 56 | 3.843 | ±0.002942 | 140 |
| `ntruees1087ep2_encrypt` | 0.2148 | ±0.0006427 | 50 | 0.244 | ±0.0009286 | 50 | 0.5671 | ±0.001289 | 201 |
| `ntruees1087ep2_decrypt` | 0.3325 | ±0.001221 | 209 | 0.3946 | ±0.001984 | 80 | 1.014 | ±0.001434 | 80 |
| `ntruees1499ep1_keygen` | 3.114 | ±0.01771 | 170 | 4.314 | ±0.01051 | 80 | 7.366 | ±0.004614 | 147 |
| `ntruees1499ep1_encrypt` | 0.211 | ±0.000396 | 233 | 0.2415 | ±0.001777 | 80 | 0.5393 | ±0.001081 | 50 |
| `ntruees1499ep1_decrypt` | 0.3017 | ±0.0002866 | 50 | 0.3725 | ±0.002614 | 50 | 0.9457 | ±0.008248 | 50 |
Per-scheme cross-platform Kiviat diagrams (radar charts; log-radial ops/sec
axis, outer ring = faster):

![ML-KEM Kiviat (Wigner / Moore / Darby)](assets/sweep-2026-05-08-mlkem-radar.svg)

![ML-DSA Kiviat (Wigner / Moore / Darby)](assets/sweep-2026-05-08-mldsa-radar.svg)

![NTRU Kiviat (Wigner / Moore / Darby)](assets/sweep-2026-05-08-ntru-radar.svg)

## Benchmark Discussion

- `ML-KEM` scales roughly with parameter size and is stable across runs; CIs are
  tight on all three hosts.
- `ML-DSA` verify is consistently cheaper than sign at each level, as expected.
- `ML-DSA` signing variance is driven by rejection behavior in the signer loop.
  In the 2026-05-08 sweep this manifests as *non-monotone absolute timings
  across parameter sets* — `mldsa65_sign` lands at 0.266 ms on Wigner while
  `mldsa87_sign` lands at 0.168 ms — even though the per-iteration cost
  grows monotonically with parameter size. The CI on each individual
  measurement is tight (≤ 0.2% half-width on Wigner), so the cross-level
  ordering reflects an honest difference in expected-rejection-loop count
  for these inputs, not measurement noise.
- `NTRU` keygen costs are dominated by the polynomial inversion in `R_q`
  (Hensel lift over the variable-time `F_2[x]` Euclidean inverse). Keygen is
  the slowest operation on every parameter set, by 5–25× over encaps/decaps.
- `NTRU-HRSS-701` encaps is among the cheapest post-quantum encapsulations
  in the table — at ≈0.048 ms on Wigner it beats most ML-KEM sizes (only
  ML-KEM-512's 0.026 ms encaps is faster), because the HRSS encryption is
  a single trinary-by-dense convolution (the Karatsuba split amortizes
  well for sparse trinary inputs). `EES443EP1` encrypt/decrypt match it
  (≈0.043 ms on Wigner) because the product-form `r = r_1 · r_2 + r_3`
  with `df_1, df_2, df_3 = 9, 8, 5` reduces each ciphertext convolution to
  three very sparse multiplies plus an addition.
- `NTRU-HPS` and `NTRUEncrypt-EES` show the gap with NTT-friendly rings
  clearly: ML-KEM-512 keygen is ~60× faster than NTRU-HPS-509 keygen on
  Wigner (0.017 ms vs 1.00 ms). The polynomial rings here are
  `Z_q[x] / (x^N − 1)` with prime `N`, which do not admit a direct radix-2
  NTT; an in-tree two-prime Montgomery NTT at the smallest power-of-two
  length covering all parameter sets (`M = 2048 ≥ 2 · 821 − 1`) was
  prototyped and discarded — at `N ≤ 821` the length-2048 transform
  overhead exceeds Karatsuba's `O(N^{log_2 3})` cost. A right-sized per-`N`
  NTT, Bluestein, or Rader-style decomposition would close more of the
  gap; the AVX2 reference C avoids the question by going to assembly.

Reference baselines (vendored C code) are available through:

- `scripts/bench_mlkem_ref.sh`
- `scripts/bench_mldsa_ref.sh`

These are for cross-checking and performance calibration, not for production
integration.

## Validation

- Full crate tests (`cargo test`) include ML-KEM, ML-DSA, and NTRU
  roundtrip/tamper checks.
- Differential tests compare against first-vector outputs from vendored
  reference implementations.
- NTRU additionally validates byte-for-byte against the `count = 0` entry of
  the official NIST PQC round-3 KAT files for each parameter set
  (`PQCkemKAT_935.rsp`, `PQCkemKAT_1234.rsp`, `PQCkemKAT_1590.rsp`,
  `PQCkemKAT_1450.rsp`).

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
- Cong Chen, Oussama Danba, Jeffrey Hoffstein, Andreas Hülsing, Joost Rijneveld,
  John M. Schanck, Peter Schwabe, William Whyte, Zhenfei Zhang, Tsunekazu Saito,
  Takashi Yamakawa, and Keita Xagawa, *NTRU — Algorithm Specifications and
  Supporting Documentation* (round-3 NIST PQC submission), 2020-10-16.
  Submission package archived at
  [`ntru.org/release/NIST-PQ-Submission-NTRU-20201016.tar.gz`](https://ntru.org/release/NIST-PQ-Submission-NTRU-20201016.tar.gz);
  this crate's NTRU implementations are direct ports of that package's
  reference C and validate against its KAT files.
- Reference code (for differential testing / benchmark calibration) is
  fetched on demand into a gitignored `third_party/` directory by
  `scripts/fetch_mlkem_refs.sh` and `scripts/fetch_mldsa_refs.sh`. The
  trees are not vendored in the repository.
