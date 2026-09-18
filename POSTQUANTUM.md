# POSTQUANTUM

## Scope

This document covers the post-quantum lattice implementations in this repo:

- `MlKem` (`ML-KEM-512/768/1024`) for key encapsulation (FIPS 203)
- `MlDsa` (`ML-DSA-44/65/87`) for signatures (FIPS 204)
- `NtruHps509`, `NtruHps677`, `NtruHps821`, `NtruHrss701` for NIST PQC round-3
  NTRU CCA-secure key encapsulation
- `NtruEes401Ep1` … `NtruEes1499Ep1` (nine parameter sets) for the IEEE
  Std 1363.1-2008 NTRUEncrypt SVES-3 public-key encryption scheme

The implementations are pure Rust in-tree arithmetic (no C/FFI in production
paths), each written from its specification: ML-KEM from FIPS 203, ML-DSA from
FIPS 204, NTRU from the round-3 specification, and NTRUEncrypt from EESS #1
v3.1. No reference code is used in the crate. Reference implementations serve
only as black-box oracles for test vectors, driven by original harnesses that
call their public API: `tests/vectors/ml_kem_ref_kat.txt` and
`tests/vectors/ml_dsa_ref_kat.txt` come from the pq-crystals reference
implementations (`scripts/gen_pq_ref_vectors.sh`, with the trees fetched on
demand into a gitignored `third_party/` directory by
`scripts/fetch_ml{kem,dsa}_refs.sh`), and
`tests/vectors/ntru_ees_sves3_reference.txt` comes from Security Innovation's
NTRUEncrypt reference at a pinned commit. Known-answer testing also runs
against NIST's round-3 NTRU KAT files and a NIST ACVP subset for ML-KEM and
ML-DSA.

Earlier versions of the ML-KEM, ML-DSA, NTRU, and NTRUEncrypt code were
transcribed or ported from reference implementations. `AUDIT.md` records the
provenance audit that found this and the clean-room rewrites that replaced
them.

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
  - `MlKem::keygen`, `MlKem::keygen_from_seed`. `keygen` draws `d` and `z`
    and then runs the pair-wise consistency test of FIPS 140-3 IG 10.3.A on
    the new pair (encapsulate under a 32-byte random message, decapsulate,
    compare, as FIPS 203 §7.1 step 4 lays it out), so it takes 96 bytes from
    the random source; `keygen_from_seed` is KeyGen_internal alone.
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

NTRU is a clean-room implementation of the round-3 specification, *NTRU —
Algorithm Specifications and Supporting Documentation* (kept as
`pubs/ntru-round3-specification.pdf`); the round-3 reference implementation
served only as a known-answer oracle, through the KAT files it produced
(`AUDIT.md` holds the provenance record). Each parameter set reproduces all
100 entries of its NIST round-3 known-answer file byte for byte (keys,
ciphertexts, shared secrets, and decapsulation): eight sampled entries under a
debug `cargo test`, all 100 under a release `cargo test`, and all 100 in any
build under `cargo test --lib -- ntru --ignored`. The four KAT files in `kat/`
are unmodified copies from NIST's round-3 submission package; `kat/README.md`
records their source and SHA-256 digests. Two details follow the KAT files
rather than the specification's wording, both recorded in `AUDIT.md`:
`Fixed_Type` sorts its keys as signed 32-bit integers, which the text describes
as unsigned, and `pack_S3` encodes `v_{5i+j-1}` where the text's index is
`v_{5i+j}`. Key generation, like encapsulation, never uses a zero polynomial:
it redraws its sampling bits once when `f` (or `g`, for HRSS) samples to zero
and panics on a second refusal, since `f = 0` would publish `h = 0` and every
ciphertext would carry `Lift(m)` in the clear.

### NTRUEncrypt (IEEE Std 1363.1-2008)

- Parameter sets (each a distinct type; eight from IEEE Std 1363.1-2008 /
  ANSI X9.98, and `NtruEes443Ep1` from EESS #1 v3.1):
  - `NtruEes401Ep1`  (112-bit security)
  - `NtruEes443Ep1`  (128-bit security)
  - `NtruEes449Ep1`  (128-bit security)
  - `NtruEes541Ep1`  (112-bit security)
  - `NtruEes677Ep1`  (192-bit security)
  - `NtruEes1087Ep1` (192-bit security)
  - `NtruEes1087Ep2` (256-bit security)
  - `NtruEes1171Ep1` (256-bit security)
  - `NtruEes1499Ep1` (256-bit security)
- APIs (each `NtruEes*Ep*` type):
  - `keygen(rng) -> (pk, sk)`
  - `encrypt(pk, msg, rng) -> Result<ct, NtruEesError>`
    (`MessageTooLong` if `msg.len() > MAX_MESSAGE_BYTES`)
  - `decrypt(sk, ct) -> Result<Vec<u8>, NtruEesError>`
  - associated constant `MAX_MESSAGE_BYTES` per parameter set
- Types (per parameter set):
  - `NtruEes*Ep*PublicKey`, `NtruEes*Ep*PrivateKey`, `NtruEes*Ep*Ciphertext`
- Shared error: `NtruEesError`

NTRUEncrypt is a public-key *encryption* scheme (not a KEM); the ciphertext
carries the message bytes directly under SVES-3 padding rather than a derived
shared secret. Validation is by interoperability with the standard authors'
reference implementation (Security Innovation's `libntruencrypt` 1.1.0, run
purely as an oracle by `scripts/ees_ref_vectors/`). For every parameter set,
`tests/vectors/ntru_ees_sves3_reference.txt` holds the reference key blobs, the
reference ciphertexts of 0-, 1-, max−1- and max-octet messages, and the exact
random octets the reference drew for each. The `define_ees_set!` tests parse
those keys and re-encode them byte-for-byte, decrypt every ciphertext, and
re-encrypt with the recorded randomness to reproduce each ciphertext exactly.
The file also holds this crate's own ciphertexts, under the reference keys and
under a key pair from this crate's `keygen`. The reference implementation
decrypted all of them and accepted those key blobs, and the tests pin them as
well. `tbuktu/libntru` describes itself as following IEEE P1363.1 but does not
interoperate with the reference: it decrypts none of the reference
ciphertexts, because its hash counters, bit orders and `g` weights differ. It is
therefore not used as a yardstick.

## Why This Design

- **In-tree arithmetic**: keeps the math auditable and lets us tune performance
  directly in Rust.
- **Strict wire parsing**: malformed encodings should fail at parse time rather
  than leak into later call sites.
- **Deterministic test entry points**: ML-KEM and ML-DSA expose explicit
  seed/randomness APIs (`keygen_from_seed`, `encaps_with_randomness`,
  `sign_with_randomness[_and_context]`) for KATs and differential tests. NTRU
  routes its KAT tests through a deterministic CSPRNG (`CtrDrbgAes256` seeded
  with the KAT's seed bytes) passed into the standard `keygen` / `encaps` entry
  points; NTRUEncrypt's interoperability tests replay the reference
  implementation's recorded random octets into `encrypt` through the same
  `Csprng` parameter.
- **`cryptography::vt` namespace**: side-channel characteristics are explicit at
  import sites.

## Serialization

The PQ schemes use a `to_wire_bytes` / `from_wire_bytes` pair on every public
key, private key, and ciphertext type — these emit the compact byte layouts
specified by FIPS 203 / FIPS 204 (for ML-KEM and ML-DSA) and by the round-3
NTRU and IEEE 1363.1 specifications (for NTRU and NTRUEncrypt). ML-KEM and
ML-DSA additionally expose a self-describing `to_key_blob` / `from_key_blob`
pair on key types, which prepends the parameter set so the parser can recover
it without an out-of-band hint. Either pair, on an ML-DSA private key,
regenerates the public key before accepting it, the check the PKCS #8
`expandedKey` path makes (`s1` and `s2` within $[-\eta, \eta]$, `t0` and `tr`
the values $\rho$, `s1` and `s2` produce); on an ML-KEM private key without
its seed, it runs the FIPS 203 §7.1 key pair check, whose pair-wise test draws
from the random source the importer takes. NTRU does not have a key-blob form: its
parameter set is bound to the type itself (e.g. `NtruHps509PrivateKey`) and the
wire layout is the only encoding. NTRUEncrypt keys are bound to their type too,
and their wire layout is the reference implementation's key blob: a tag, the
OID length and the three-octet parameter-set OID precede the packed key, so a
key for another parameter set is rejected at parse time. EESS #1 v3.1 §10.2.1
leaves the key format to the implementation ("as long as it is unambiguous"),
and a private key is imported only if it passes the standard's key pair
validation (kpv3, §10.2.4.1).

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

**Implementation notes.** Coefficients stay canonical in $[0, q)$; products are
reduced by a Barrett reduction derived in the source (shift 25, multiplier
$\lfloor 2^{25}/q \rfloor = 10079$) and a masked conditional subtraction, with no
Montgomery form. Both NTT tables are computed at compile time from $\zeta = 17$
and checked against FIPS 203 Appendix A. Compression multiplies by
$\lceil 2^{33}/q \rceil$ and shifts by 33 (Granlund–Montgomery), so no division
touches secret data, and message encoding and the implicit-rejection selection
are branch-free.

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

**Implementation notes.** Coefficients stay in $[0, q)$ with a Barrett reduction
($m = \lfloor 2^{64}/q \rfloor$) instead of Montgomery multiplication, and the
$\zeta$ table is computed at compile time from $\zeta = 1753$. Decompose,
Power2Round, MakeHint and the rejection tests run without secret-dependent
branches, table indices or divisions, using multiply-and-shift divisions
derived at compile time and masks; the rejection samplers of Algorithms 29 and
31 branch, as the standard's own loops do, only on which XOF candidates are
discarded. Every signing attempt evaluates all rejection tests, so timing
reveals only that an attempt was rejected; in the deterministic variant the
attempt count is a function of the message, the leak FIPS 204 §3.6.1 names,
which is why hedged signing is the default.
Signing stops after 814 attempts, the smallest cap FIPS 204 Appendix C allows,
and a private key whose $s_1$ or $s_2$ lies outside $[-\eta, \eta]$ makes
signing return `None`.

### NTRU (NIST PQC round 3)

At a high level (HPS variants):

1. `keygen` samples a trinary $f$ (IID-uniform) and a trinary $g$ of fixed
   weight $q/8 - 2$, computes $f^{-1} \bmod 3$ and $(g\cdot f)^{-1} \bmod q$,
   and, with $G = 3g$ and $v = (G\cdot f)^{-1} \in S_q$, derives the public
   polynomial $h = v\cdot G\cdot G$ and its inverse $h_q = v\cdot f\cdot f$
   in $S_q$. The private key bundles $f$, $f^{-1} \bmod 3$, $h_q$, and a
   32-byte PRF key for implicit rejection.
2. `encaps` samples $(r, m)$ (IID for $r$, fixed-weight for $m$), derives
   the shared secret
   `K = SHA3-256(pack3(r) ‖ pack3(m))`, lifts
   $r$ into $\mathbb{Z}_q$, and emits the ciphertext
   $c = r\cdot h + \text{lift}(m)$ packed sum-zero. `encaps` never creates a
   zero polynomial. The specification's sampler reduces each coin byte mod 3,
   so it can return $r = 0$ (and, for HRSS, $m = 0$), outside its own sample
   space; with uniform coins a `Ternary` polynomial is zero with probability
   $(86/256)^{n-1}$, below $2^{-799}$ for every set. Such coins are wiped and
   a fresh draw is taken, which yields the specification's sampler
   conditioned on its sample space: the output distribution changes only on
   that event, and an implementation that never excludes zero still
   decapsulates every ciphertext `encaps` emits. A second refused draw in a
   row panics, because the random source is broken. The zero tests are
   branch-free, and the retry count reveals only whether a discarded draw was
   refused.
3. `decaps` recovers $(r, m)$ via the trapdoor $(f, f^{-1}_3, h^{-1})$,
   checks that $r$ is ternary and non-zero, that $m$ has weight $q/8 - 2$
   (HPS) or is non-zero (HRSS), and that the ciphertext's padding bits are
   zero, and returns
   `K = SHA3-256(pack3(r) ‖ pack3(m))` on
   success or `K = SHA3-256(prf ‖ c)` on any
   consistency failure (implicit rejection). Requiring $r \neq 0$ follows the
   specification's definition of $T$ as the non-zero ternary polynomials, and
   zero polynomials serve no purpose: with $r = 0$ the ciphertext is
   $\text{lift}(m)$, which exposes $m$ and $K$. The owner decided on
   2026-09-11 that `encaps` never creates them and `decaps` rejects them, so
   every ciphertext `encaps` emits decapsulates to the sender's $K$.

HRSS-701 differs from the HPS sets in four places: $f$ and $g$ come from the
`sample_iid_plus` distribution (each polynomial $v$ is sampled IID-uniform
mod 3 and then post-conditioned by conditionally negating its even-indexed
coefficients to enforce $\langle x\cdot v, v \rangle \geq 0$), the keygen
uses $g \gets 3\cdot(x - 1)\cdot g$ instead of $g \gets 3\cdot g$, the
message-space check on $m$ reduces to $m \neq 0$, and the encryption lift is
$\mathrm{Lift}(m) = (x - 1)\cdot S_3\!\left(m / (x - 1)\right)$ rather than
the bare $\mathbb{Z}_3 \to \mathbb{Z}_q$ map.

### NTRUEncrypt (IEEE Std 1363.1-2008)

At a high level (SVES-3, the only padding mode this crate implements). Every
encoding convention is listed in the module documentation of
`src/public_key/ntru_ees_core.rs`, with its section of EESS #1 v3.1 (the
public edition of the specification behind IEEE 1363.1 and X9.98, 2015).

1. `keygen` samples the private component $F$ and retries until
   $f = 1 + 3F$ is invertible in $R_q = \mathbb{Z}_q[x]/(x^N - 1)$. $F$ is a
   trinary polynomial with $df$ coefficients $+1$ and $df$ coefficients $-1$
   for eight parameter sets, and product form $F = F_1 \cdot F_2 + F_3$ for
   `EES443EP1`. It then samples $g$ with $dg + 1$ coefficients $+1$ and $dg$
   coefficients $-1$ until $g$ is invertible too (EESS #1 v3.1 §10.2.1), and
   publishes $h = 3 \cdot f^{-1} \cdot g \bmod q$. The private key stores $F$
   next to $h$, trit-packed or as index lists, whichever is shorter. Modulo
   2 both $f$ and $g$ take the value 1 at $x = 1$, so a candidate fails only
   by sharing a factor with $\Phi_N(x)$ over $\mathbb{F}_2$, whose
   irreducible factors have degree $\mathrm{ord}_N(2) \ge 73$ for every set
   here; eight failures in a row, or 256 rejected index draws in a row, are
   reported as a broken random source by a panic.
2. `encrypt(pk, msg)` rejects messages longer than `MAX_MESSAGE_BYTES`, draws
   the random component $b$ (`db / 8` octets) and forms
   `M = b ‖ len ‖ msg ‖ zeros`. The blinding polynomial $r$, the same shape as
   $F$, comes from the index generation function IGF-2 over
   `sData = OID ‖ msg ‖ b ‖ hTrunc`. IGF-2 hashes `sData` once and expands the
   digest with `Hash(Z ‖ I2OSP(counter, 4))`. The encrypter computes
   $R = r \cdot h \bmod q$ and maps $M$ to trits, three bits to two trits. It
   masks those trits with MGF-TP-1 of $R \bmod 4$ and requires the masked
   representative $m'$ to hold at least $dm0$ of each trit value, drawing a new
   $b$ otherwise. The mask is hash output, so the refusal probability per
   attempt is exactly $1 - \Pr[\text{every count} \ge dm0]$ under the
   multinomial on $N$ uniform trits: $3.49 \times 10^{-2}$ for `ees401ep1`,
   $9.74 \times 10^{-4}$ for `ees443ep1`, $0.155$ for `ees449ep1` and below
   $10^{-8}$ for the other six sets (the table in `ntru_ees_core.rs`, checked
   by a test that measures every set, and for `ees443ep1` by a million-trial
   run: 1038 refusals in 1,001,038 attempts). Sixty-four refusals in a row,
   below $0.155^{64} < 2^{-172}$ for a working random source, are a panic. The
   ciphertext is
   $e = R + m' \bmod q$, packed at 11 bits per coefficient, most significant
   bit first.
3. `decrypt(sk, e)` computes $e + 3 \cdot F \cdot e \bmod q$, lifts it into
   $[-q/2, q/2)$ and reduces mod 3 to recover $m'$. It recovers
   $R = e - m' \bmod q$, removes the mask, decodes $M$, re-derives $r$ from
   the recovered `msg` and `b`, and checks $r \cdot h = R$. Six checks run
   before the single accept/reject decision, and their results fold into one
   flag: the weight check, trit-pair validity, the length bound, the zero
   padding, the bits past the padding and the re-encryption comparison. Any
   failure returns `NtruEesError::InvalidCiphertext`. The module
   documentation lists the timing dependence that remains: the `sData` hash
   length follows the recovered message length, rejection-sampling loops run
   a data-dependent number of times, and sparse convolutions touch memory at
   secret indices.

Of the nine parameter sets, only `EES443EP1` uses product form for $F$ and
$r$. Each factor has $df_i$ coefficients $+1$ and $df_i$ coefficients $-1$,
with $(df_1, df_2, df_3) = (9, 8, 5)$. Each multiplication by $F$ or $r$ then
reduces to three sparse convolutions plus an addition, which is why the
`EES443EP1` row is disproportionately fast in the benchmark table below.

As specified, `EES443EP1` and `EES1499EP1` ciphertexts are malleable. For
these two degrees the last trit pair writes two bits past the zero padding;
EESS #1 v3.1 §10.2.3 step i drops them unchecked, and the standard authors'
reference implementation behaves the same way. Adding 1 to the top ciphertext
coefficient therefore leaves the plaintext unchanged whenever the mask
coefficient there is 0 or −1, about two times in three, and subtracting 2 does
so in the remaining third, which defeats IND-CCA2 for those sets. (`EES677EP1`
has one such bit, but its pair also writes the last padding bit, which is
checked.)

The crate closes the hole with a check that goes beyond the letter of
§10.2.3, decided by the owner on 2026-09-11: decryption also fails unless
every decoded bit past the zero padding is zero. The check cannot reject an
honest ciphertext. An honest encryptor's bits there are the zeros that §10.2.2
step g appends to reach a multiple of three bits, and when decryption recovers
its masked message the trit pairs decode back to exactly those bits.
Interoperability is unchanged, and the reference vectors still pass in both
directions. The crate does reject tampered ciphertexts that the reference
implementation accepts. Tests in `ntru_ees_core` measure how often each
tampering used to keep the plaintext, and confirm that none now decrypts.

## Working Examples

Each example below is exercised end-to-end by
`tests/manual_examples.rs::manual_postquantum_examples` (same call shape and
roundtrip assertions; the test uses its own DRBG seed rather than the per-block
seed in each snippet).

### ML-KEM end-to-end + wire/blob roundtrips

```rust
use cryptography::vt::{
    MlKem, MlKemParameterSet, MlKemPrivateKey, MlKemPublicKey,
};
use cryptography::CtrDrbgAes256;

let mut rng = CtrDrbgAes256::new(&[0x11u8; 48]);

let (pk, sk) = MlKem::keygen(MlKemParameterSet::MlKem768, &mut rng).expect("keygen");
let (ct, ss_sender) = MlKem::encaps(&pk, &mut rng);
let ss_receiver = MlKem::decaps(&sk, &ct).expect("decaps");
assert_eq!(ss_sender.to_wire_bytes(), ss_receiver.to_wire_bytes());

let pk_wire = pk.to_wire_bytes();
let pk_round = MlKemPublicKey::from_wire_bytes(MlKemParameterSet::MlKem768, &pk_wire).expect("pk");
assert_eq!(pk_round, pk);

let sk_blob = sk.to_key_blob();
let sk_round = MlKemPrivateKey::from_key_blob(&sk_blob, &mut rng).expect("sk");
assert_eq!(sk_round, sk);
```

### ML-DSA sign/verify + context + signature wire roundtrip

```rust
use cryptography::vt::{
    MlDsa, MlDsaParameterSet, MlDsaSignature,
};
use cryptography::CtrDrbgAes256;

let mut rng = CtrDrbgAes256::new(&[0x22u8; 48]);
let (pk, sk) = MlDsa::keygen(MlDsaParameterSet::MlDsa65, &mut rng);

let sig = MlDsa::sign(&sk, b"release manifest", &mut rng).expect("sign");
assert!(MlDsa::verify(&pk, b"release manifest", &sig));
assert!(!MlDsa::verify(&pk, b"tampered", &sig));

let ctx = b"bundle:v1";
let rnd = [0x5Cu8; 32];
let sig_ctx = MlDsa::sign_with_randomness_and_context(&sk, b"payload", &rnd, ctx).expect("sign");
assert_eq!(MlDsa::verify_with_context(&pk, b"payload", &sig_ctx, ctx), Some(true));
assert_eq!(MlDsa::verify_with_context(&pk, b"payload", &sig_ctx, b"bundle:v2"), Some(false));

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

### NTRUEncrypt encrypt/decrypt + wire roundtrip

```rust
use cryptography::vt::{
    NtruEes443Ep1, NtruEes443Ep1Ciphertext, NtruEes443Ep1PublicKey, NtruEesError,
};
use cryptography::CtrDrbgAes256;

let mut rng = CtrDrbgAes256::new(&[0x44u8; 48]);

let (pk, sk) = NtruEes443Ep1::keygen(&mut rng);

let msg: &[u8] = b"public-key encryption, not a KEM";
assert!(msg.len() <= NtruEes443Ep1::MAX_MESSAGE_BYTES);

let ct = NtruEes443Ep1::encrypt(&pk, msg, &mut rng).expect("encrypt");
let pt = NtruEes443Ep1::decrypt(&sk, &ct).expect("decrypt");
assert_eq!(pt, msg);

let pk_round =
    NtruEes443Ep1PublicKey::from_wire_bytes(&pk.to_wire_bytes()).expect("pk");
let ct_round =
    NtruEes443Ep1Ciphertext::from_wire_bytes(&ct.to_wire_bytes()).expect("ct");
assert_eq!(pk_round, pk);
assert_eq!(ct_round, ct);

let too_big = vec![0u8; NtruEes443Ep1::MAX_MESSAGE_BYTES + 1];
let err = NtruEes443Ep1::encrypt(&pk, &too_big, &mut rng).unwrap_err();
assert_eq!(err, NtruEesError::MessageTooLong);
```

The other eight parameter sets (`NtruEes401Ep1`, `NtruEes449Ep1`,
`NtruEes541Ep1`, `NtruEes677Ep1`, `NtruEes1087Ep1`, `NtruEes1087Ep2`,
`NtruEes1171Ep1`, `NtruEes1499Ep1`) expose identical `keygen` / `encrypt` /
`decrypt` shapes; the byte sizes and `MAX_MESSAGE_BYTES` differ per set.

## Parameter Comparison

### ML-KEM: Security vs. Cost

**Key and ciphertext sizes (bytes; FIPS 203 §7)**

| Parameter | Security | Public Key | Private Key | Ciphertext | Shared Secret |
|---|:---:|---:|---:|---:|---:|
| ML-KEM-512  | NIST 1 |   800 | 1 632 |   768 | 32 |
| ML-KEM-768  | NIST 3 | 1 184 | 2 400 | 1 088 | 32 |
| ML-KEM-1024 | NIST 5 | 1 568 | 3 168 | 1 568 | 32 |

**Throughput across parameter sets and platforms** — each axis is an operation
(keygen / encaps / decaps) for one parameter set; outer ring = faster. ±90%
CI half-widths are in the benchmark tables below.

![ML-KEM ops/sec radar (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-mlkem-radar.svg)

### ML-DSA: Security vs. Cost

**Key and signature sizes (bytes; FIPS 204 Table 2)**

| Parameter | Security | Public Key | Private Key | Signature |
|---|:---:|---:|---:|---:|
| ML-DSA-44 | NIST 2 | 1 312 | 2 560 | 2 420 |
| ML-DSA-65 | NIST 3 | 1 952 | 4 032 | 3 309 |
| ML-DSA-87 | NIST 5 | 2 592 | 4 896 | 4 627 |

**Throughput across parameter sets and platforms** — each axis is an operation
(keygen / sign / verify) for one parameter set; outer ring = faster. ±90%
CI half-widths are in the benchmark tables below.

![ML-DSA ops/sec radar (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-mldsa-radar.svg)

### NTRU: Security vs. Cost

**Key and ciphertext sizes (bytes; round-3 submission Table 2.1)**

| Parameter | Security | Public Key | Private Key | Ciphertext | Shared Secret |
|---|:---:|---:|---:|---:|---:|
| NtruHps509  | NIST 1 |   699 |   935 |   699 | 32 |
| NtruHrss701 | NIST 1 | 1 138 | 1 450 | 1 138 | 32 |
| NtruHps677  | NIST 3 |   930 | 1 234 |   930 | 32 |
| NtruHps821  | NIST 5 | 1 230 | 1 590 | 1 230 | 32 |

**Throughput across parameter sets and platforms** — each axis is an operation
(keygen / encaps / decaps) for one parameter set; outer ring = faster. ±90%
CI half-widths are in the benchmark tables below.

![NTRU ops/sec radar (i5-8259U / Apple M1 / Cortex-X925 / Cortex-A76)](assets/sweep-2026-09-17-ntru-radar.svg)

### NTRUEncrypt (IEEE 1363.1): Security vs. Cost

**Key, ciphertext, and message sizes (bytes; key blobs and ciphertexts in the
reference implementation's wire format, message limits from the parameter
tables)**

| Parameter | Security | Public Key | Private Key | Ciphertext | Max Message |
|---|:---:|---:|---:|---:|---:|
| EES401EP1  | 112-bit |   557 |   638 |   552 |  60 |
| EES443EP1  | 128-bit |   615 |   665 |   610 |  49 |
| EES449EP1  | 128-bit |   623 |   713 |   618 |  67 |
| EES541EP1  | 112-bit |   749 |   858 |   744 |  86 |
| EES677EP1  | 192-bit |   936 | 1 072 |   931 | 101 |
| EES1087EP1 | 192-bit | 1 500 | 1 674 | 1 495 | 178 |
| EES1087EP2 | 256-bit | 1 500 | 1 718 | 1 495 | 170 |
| EES1171EP1 | 256-bit | 1 616 | 1 851 | 1 611 | 186 |
| EES1499EP1 | 256-bit | 2 067 | 2 285 | 2 062 | 247 |

Public and private keys are the reference implementation's key blobs. Each
starts with a tag, the OID length and the three-octet parameter-set OID,
followed by $h$ packed at 11 bits per coefficient (`⌈11N/8⌉` octets, which is
also the ciphertext length). A private key appends $F$ in whichever packing is
shorter. Six of the dense sets use five trits per octet (`⌈N/5⌉` octets).
`EES1087EP1`, `EES1499EP1` and the product-form `EES443EP1` use index lists at
`⌈log₂ N⌉` bits per index. The public key is kept because SVES-3 decryption
re-encrypts to validate the ciphertext. The message limit is
$\lfloor \lfloor N/2 \rfloor \cdot 3/8 \rfloor - 1 - db/8$, the
`maxMsgLenBytes` of each parameter table. `EES443EP1` uses $db = 256$ bits, as
its reference definition does, so its limit is 49.

### Cross-scheme comparison at NIST Level 3 / 192-bit security

| Metric | ML-KEM-768 | ML-DSA-65 | NTRU-HPS-677 | NTRUEncrypt EES677EP1 |
|---|---:|---:|---:|---:|
| Function | KEM | Signature | KEM | PKE |
| Quoted security | NIST 3 | NIST 3 | NIST 3 | 192-bit |
| Public key (bytes) | 1 184 | 1 952 | 930 | 936 |
| Private key (bytes) | 2 400 | 4 000 | 1 234 | 1 072 |
| Payload (bytes) | 1 088 CT + 32 SS | 3 309 sig | 930 CT + 32 SS | 931 CT (≤ 101 B msg) |
| Keygen Tolkien (ms/op) | 0.02318 | 0.09676 | 1.128 | 1.126 |
| Primary op Tolkien (ms/op) | 0.01126 encaps | 0.2387 sign | 0.08611 encaps | 0.174 encrypt |
| Secondary op Tolkien (ms/op) | 0.012 decaps | 0.02192 verify | 0.09966 decaps | 0.267 decrypt |

90% CI half-widths for each entry are in the per-scheme benchmark tables
below. The four schemes are not interchangeable — KEM, signature, and
public-key encryption serve different functional roles — but several
qualitative observations are visible directly in the table at this
security tier:

- ML-DSA signing is ~10× slower than ML-KEM encapsulation due to the
  rejection-sampling loop; ML-DSA verification comes in slightly below ML-KEM
  decapsulation on Tolkien (0.031 ms vs 0.037 ms). Rejection-sampling variance
  also shows up as *non-monotone* absolute sign timing across ML-DSA parameter
  sets — see the "Benchmark Discussion" notes below.
- The two NTRU-family schemes carry the smallest public keys at this tier
  (≈930 bytes), but pay an order of magnitude more per keygen than ML-KEM
  (≈1.1 ms vs 0.035 ms) because the polynomial inversion in $R_q$ does not
  benefit from an NTT.
- NTRUEncrypt encrypt/decrypt at this tier are roughly 2× the cost of
  NTRU-HPS-677 encaps/decaps; the SVES-3 re-encryption check inside
  `decrypt` accounts for the bulk of the gap.

## Benchmarks

> **These are the clean-room implementations.** The tables below are the
> 2026-09-17 sweep, the first to post-date the rewrites and conformance
> changes of this year's audit round, so they measure what the crate ships
> rather than what preceded it. On the development machine those rewrites cost
> ML-KEM-768 keygen, encaps and decaps 1.38×, 1.65× and 1.73×; ML-DSA-65
> keygen, sign and verify 1.05×, 1.30× and 1.16×; and NTRU round-3 key
> generation about 2×.

Measured with [pilot-bench](https://github.com/darrelllong/pilot-bench) via:

```text
bash scripts/bench_all_pk_full.sh
```

Numbers below are `ms/op`, with **90%** CI half-width and rounds run. The
2026-09-17 sweep was driven with `PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90
PILOT_SESSION_LIMIT=300` (10% CI half-width target, autocorrelation tolerance
0.2, ≥ 50 rounds minimum sample size); the exact invocations are recorded in
[`bench/sweep-2026-09-17/README.md`](bench/sweep-2026-09-17/README.md), which
is the canonical record of what each host actually ran. Note that
`scripts/bench_all_pk_full.sh` defaults `PILOT_PRESET=quick`, so a re-run
without overriding the env var would not reproduce these numbers. Each host
ran one case at a time:

- Intel Core i5-8259U (`dmz`, Linux, idle)
- Apple M1 (`tolkien`, macOS; no Mac is idle, and its background load is
  recorded with the run)
- Arm Cortex-X925 (`baase`, Linux, idle)
- Arm Cortex-A76 (`darby`, Raspberry Pi 5, Linux, idle)

### ML-KEM (FIPS 203)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mlkem512_keygen | 0.1871 | ±0.0008895 | 82 | 0.08829 | ±6.326e-05 | 83 | 0.06768 | ±8.45e-05 | 80 | 0.2678 | ±0.0001713 | 80 |
| mlkem512_encaps | 0.04269 | ±0.0002437 | 80 | 0.01885 | ±7.105e-06 | 89 | 0.01405 | ±9.193e-05 | 380 | 0.05945 | ±0.0001419 | 50 |
| mlkem512_decaps | 0.05674 | ±0.0002279 | 200 | 0.02376 | ±1.705e-05 | 80 | 0.0183 | ±0.001454 | 230 | 0.0746 | ±0.0001208 | 204 |
| mlkem768_keygen | 0.3002 | ±0.001253 | 260 | 0.14 | ±0.0001843 | 110 | 0.1127 | ±0.007714 | 140 | 0.4271 | ±0.001196 | 50 |
| mlkem768_encaps | 0.06158 | ±0.0002377 | 140 | 0.02455 | ±9.881e-06 | 200 | 0.01863 | ±0.000168 | 170 | 0.07864 | ±0.0002274 | 174 |
| mlkem768_decaps | 0.07932 | ±0.0001851 | 80 | 0.03113 | ±1.166e-05 | 111 | 0.02464 | ±0.001892 | 82 | 0.09907 | ±0.0002195 | 50 |
| mlkem1024_keygen | 0.4507 | ±0.001826 | 80 | 0.2111 | ±0.0001812 | 80 | 0.1726 | ±0.01085 | 80 | 0.6492 | ±0.01782 | 50 |
| mlkem1024_encaps | 0.1082 | ±0.0006697 | 358 | 0.03195 | ±1.619e-05 | 238 | 0.02486 | ±0.002023 | 80 | 0.1297 | ±0.0007908 | 230 |
| mlkem1024_decaps | 0.1234 | ±0.0002595 | 80 | 0.0405 | ±2.208e-05 | 80 | 0.03143 | ±0.0002111 | 80 | 0.1288 | ±0.0003208 | 140 |

### ML-DSA (FIPS 204)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mldsa44_keygen | 0.1429 | ±0.0009877 | 119 | 0.06244 | ±5.137e-05 | 55 | 0.04558 | ±0.003758 | 89 | 0.2163 | ±0.0002564 | 83 |
| mldsa44_sign | 0.4862 | ±0.02274 | 50 | 0.1838 | ±0.006897 | 50 | 0.1595 | ±0.00639 | 170 | 0.7288 | ±0.03143 | 110 |
| mldsa44_verify | 0.0537 | ±0.0004983 | 88 | 0.02118 | ±2.543e-05 | 80 | 0.01765 | ±0.0002555 | 80 | 0.07575 | ±0.0002229 | 50 |
| mldsa65_keygen | 0.2559 | ±0.001288 | 80 | 0.1159 | ±9.602e-05 | 80 | 0.08235 | ±0.004982 | 85 | 0.385 | ±0.0004955 | 50 |
| mldsa65_sign | 0.7712 | ±0.03275 | 50 | 0.2902 | ±0.01529 | 81 | 0.2521 | ±0.01287 | 110 | 1.125 | ±0.05218 | 110 |
| mldsa65_verify | 0.07649 | ±0.0008272 | 80 | 0.02918 | ±2.876e-05 | 170 | 0.02471 | ±0.0002269 | 200 | 0.1052 | ±0.0003283 | 50 |
| mldsa87_keygen | 0.3972 | ±0.001913 | 50 | 0.1693 | ±0.0001286 | 140 | 0.1195 | ±0.00793 | 82 | 0.6127 | ±0.000744 | 80 |
| mldsa87_sign | 0.8101 | ±0.04629 | 80 | 0.3039 | ±0.01665 | 50 | 0.2602 | ±0.01361 | 80 | 1.18 | ±0.06751 | 80 |
| mldsa87_verify | 0.1162 | ±0.0003239 | 110 | 0.04249 | ±5.373e-05 | 80 | 0.036 | ±0.002789 | 110 | 0.1545 | ±0.0006319 | 146 |

### NTRU (NIST PQC round 3)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ntruhps509_keygen | 2.273 | ±0.006223 | 80 | 1.899 | ±0.001022 | 50 | 1.176 | ±0.03927 | 50 | 3.689 | ±0.04466 | 145 |
| ntruhps509_encaps | 0.1028 | ±0.002729 | 50 | 0.07319 | ±4.764e-05 | 80 | 0.04606 | ±0.000221 | 350 | 0.1439 | ±0.000243 | 620 |
| ntruhps509_decaps | 0.1668 | ±0.0005277 | 50 | 0.1285 | ±8.205e-05 | 50 | 0.08181 | ±0.005714 | 380 | 0.2577 | ±0.0004326 | 80 |
| ntruhps677_keygen | 2.178 | ±0.009497 | 110 | 1.227 | ±0.001081 | 58 | 1.04 | ±0.0004504 | 80 | 3.333 | ±0.0004348 | 80 |
| ntruhps677_encaps | 0.1383 | ±0.001108 | 116 | 0.08563 | ±8.291e-05 | 290 | 0.06004 | ±0.004047 | 50 | 0.1922 | ±0.0003309 | 620 |
| ntruhps677_decaps | 0.1757 | ±0.00322 | 110 | 0.09114 | ±9.64e-05 | 80 | 0.08065 | ±0.006574 | 140 | 0.2595 | ±0.0003151 | 50 |
| ntruhps821_keygen | 3.778 | ±0.0137 | 290 | 3.629 | ±0.00147 | 50 | 1.885 | ±0.1254 | 50 | 5.977 | ±0.002638 | 115 |
| ntruhps821_encaps | 0.1809 | ±0.001215 | 56 | 0.144 | ±7.791e-05 | 1161 | 0.07959 | ±0.0003806 | 350 | 0.2567 | ±0.00046 | 85 |
| ntruhps821_decaps | 0.2886 | ±0.01354 | 50 | 0.2552 | ±7.016e-05 | 260 | 0.1324 | ±0.00816 | 593 | 0.4345 | ±0.001431 | 50 |
| ntruhrss701_keygen | 2.594 | ±0.007373 | 143 | 1.432 | ±0.0008151 | 50 | 1.263 | ±0.001043 | 230 | 4.035 | ±0.001072 | 50 |
| ntruhrss701_encaps | 0.08754 | ±0.0007937 | 412 | 0.0462 | ±4.588e-05 | 200 | 0.04117 | ±0.002256 | 200 | 0.1248 | ±0.0003064 | 50 |
| ntruhrss701_decaps | 0.1988 | ±0.001434 | 80 | 0.1037 | ±9.147e-05 | 80 | 0.09187 | ±0.005147 | 170 | 0.2985 | ±0.0002326 | 110 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Apple M1 ms/op | Apple M1 ±CI (90%) | Apple M1 Runs | Cortex-X925 ms/op | Cortex-X925 ±CI (90%) | Cortex-X925 Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ntruees401ep1_keygen | 0.6887 | ±0.001179 | 175 | 0.5246 | ±0.0004164 | 50 | 0.3487 | ±0.01619 | 200 | 0.8404 | ±0.001428 | 52 |
| ntruees401ep1_encrypt | 0.1859 | ±0.006327 | 50 | 0.07951 | ±0.002991 | 50 | 0.0585 | ±0.004474 | 80 | 0.1745 | ±0.005168 | 50 |
| ntruees401ep1_decrypt | 0.2731 | ±0.008649 | 141 | 0.1275 | ±0.0001506 | 80 | 0.09865 | ±0.007037 | 80 | 0.2877 | ±0.0006532 | 50 |
| ntruees443ep1_keygen | 0.6744 | ±0.001221 | 81 | 0.5126 | ±0.0003972 | 54 | 0.3319 | ±0.0003822 | 110 | 0.8674 | ±0.0008467 | 55 |
| ntruees443ep1_encrypt | 0.03703 | ±0.0002395 | 50 | 0.02425 | ±0.0001174 | 50 | 0.0171 | ±0.0002855 | 115 | 0.04812 | ±0.000345 | 51 |
| ntruees443ep1_decrypt | 0.06392 | ±0.0005043 | 50 | 0.0354 | ±8.65e-05 | 80 | 0.02665 | ±0.002204 | 388 | 0.07573 | ±0.0004536 | 50 |
| ntruees449ep1_keygen | 0.9161 | ±0.001308 | 80 | 0.6229 | ±0.0005313 | 530 | 0.441 | ±0.03344 | 50 | 1.046 | ±0.001349 | 80 |
| ntruees449ep1_encrypt | 0.1897 | ±0.01125 | 50 | 0.1152 | ±0.007062 | 50 | 0.08333 | ±0.005972 | 200 | 0.2541 | ±0.01469 | 50 |
| ntruees449ep1_decrypt | 0.2983 | ±0.001335 | 140 | 0.1644 | ±0.0001591 | 350 | 0.121 | ±0.006894 | 50 | 0.3814 | ±0.001281 | 110 |
| ntruees541ep1_keygen | 0.6865 | ±0.001502 | 81 | 0.438 | ±0.0004614 | 88 | 0.4069 | ±0.02818 | 176 | 0.7641 | ±0.001555 | 50 |
| ntruees541ep1_encrypt | 0.07362 | ±0.0004721 | 171 | 0.04595 | ±5.644e-05 | 114 | 0.03321 | ±0.001745 | 86 | 0.1028 | ±0.0004595 | 230 |
| ntruees541ep1_decrypt | 0.1631 | ±0.001077 | 50 | 0.0765 | ±0.0001244 | 110 | 0.05759 | ±0.004498 | 50 | 0.1777 | ±0.001108 | 50 |
| ntruees677ep1_keygen | 1.201 | ±0.001724 | 50 | 0.7067 | ±0.0004068 | 111 | 0.6008 | ±0.04595 | 230 | 1.433 | ±0.001552 | 140 |
| ntruees677ep1_encrypt | 0.2973 | ±0.0008163 | 200 | 0.1475 | ±0.0001222 | 85 | 0.1052 | ±0.00866 | 115 | 0.3513 | ±0.0005818 | 80 |
| ntruees677ep1_decrypt | 0.5705 | ±0.00425 | 170 | 0.2684 | ±0.0002338 | 56 | 0.2185 | ±0.01801 | 202 | 0.6391 | ±0.001865 | 50 |
| ntruees1087ep1_keygen | 1.516 | ±0.006869 | 110 | 0.9854 | ±0.00113 | 80 | 1.171 | ±0.09561 | 80 | 1.801 | ±0.002088 | 110 |
| ntruees1087ep1_encrypt | 0.1931 | ±0.002727 | 53 | 0.09963 | ±8.105e-05 | 80 | 0.07491 | ±0.00362 | 178 | 0.2237 | ±0.001594 | 80 |
| ntruees1087ep1_decrypt | 0.3882 | ±0.003003 | 50 | 0.1936 | ±0.0005642 | 50 | 0.1352 | ±0.007618 | 170 | 0.4255 | ±0.001437 | 80 |
| ntruees1087ep2_keygen | 1.638 | ±0.005439 | 170 | 1.043 | ±0.002625 | 50 | 1.033 | ±0.0843 | 56 | 1.897 | ±0.00293 | 84 |
| ntruees1087ep2_encrypt | 0.3456 | ±0.002335 | 54 | 0.1755 | ±0.0001843 | 50 | 0.1359 | ±0.01081 | 200 | 0.3984 | ±0.00244 | 50 |
| ntruees1087ep2_decrypt | 0.7466 | ±0.003554 | 50 | 0.3552 | ±0.0007278 | 110 | 0.2521 | ±0.01964 | 80 | 0.7834 | ±0.002712 | 80 |
| ntruees1171ep1_keygen | 1.882 | ±0.01217 | 50 | 1.114 | ±0.001566 | 140 | 1.041 | ±0.06569 | 110 | 2.254 | ±0.002825 | 1250 |
| ntruees1171ep1_encrypt | 0.3446 | ±0.001458 | 80 | 0.1685 | ±0.0002223 | 50 | 0.1354 | ±0.006482 | 140 | 0.4011 | ±0.003179 | 80 |
| ntruees1171ep1_decrypt | 0.7648 | ±0.004506 | 50 | 0.3112 | ±0.0004232 | 50 | 0.2515 | ±0.02092 | 81 | 0.7468 | ±0.003089 | 57 |
| ntruees1499ep1_keygen | 3.138 | ±0.03615 | 140 | 1.771 | ±0.001282 | 110 | 1.548 | ±0.06714 | 143 | 4.254 | ±0.005327 | 51 |
| ntruees1499ep1_encrypt | 0.3272 | ±0.007406 | 50 | 0.1629 | ±0.0002058 | 50 | 0.1307 | ±0.00626 | 80 | 0.3812 | ±0.00372 | 50 |
| ntruees1499ep1_decrypt | 0.5475 | ±0.004155 | 170 | 0.3071 | ±0.0003582 | 86 | 0.2431 | ±0.02006 | 599 | 0.6982 | ±0.002581 | 83 |

## Benchmark Discussion

- `ML-KEM` scales roughly with parameter size and is stable across runs; CIs
  are tight on Tolkien and Twilight, while Heinlein needs thousands of rounds
  to converge on its noisier silicon but still meets the 10% target.
- `ML-DSA` verify is consistently cheaper than sign at each level, as expected.
- `ML-DSA` signing variance is driven by rejection behavior in the signer loop.
  In the 2026-08-11 sweep this manifests as *non-monotone absolute timings
  across parameter sets* — `mldsa65_sign` lands at 0.332 ms on Tolkien while
  `mldsa87_sign` lands at 0.214 ms — even though the per-iteration cost
  grows monotonically with parameter size. The CI on each individual
  measurement is tight (≤ 1.3% half-width on Tolkien), but a tight CI of the
  mean only constrains within-run variance, not across-seed reproducibility:
  the cross-level ordering is plausibly explained by the rejection-loop
  count distribution differing across parameter sets for these particular
  inputs, but ruling out a slow-tail draw on the smaller `mldsa65_sign` sample
  would require a multi-seed reproduction.
- `NTRU` keygen costs are dominated by the polynomial inversion in $R_q$
  (Hensel lift over the variable-time $\mathbb{F}_2[x]$ Euclidean inverse). Keygen is
  the slowest operation on every parameter set; on Tolkien the keygen-vs-other
  ratios span 6.5× (HPS-509 keygen / HPS-509 decaps) up to 25.3× (HRSS-701
  keygen / HRSS-701 encaps).
- `NTRU-HRSS-701` encaps is the cheapest of the NTRU-family encapsulations
  on Tolkien (≈0.047 ms), because HRSS encryption is a single
  trinary-by-dense convolution (the Karatsuba split amortizes well for
  sparse trinary inputs). It is still slower than ML-KEM encaps at
  comparable security on Tolkien — ML-KEM-512 lands at ≈0.020 ms and
  ML-KEM-768 at ≈0.033 ms, with only ML-KEM-1024 (≈0.051 ms) costing
  more — because the NTT-friendly ring used by ML-KEM
  remains a structural advantage that dense-trinary convolution cannot
  close. `EES443EP1` encrypt/decrypt are even cheaper than HRSS-701 encaps
  on Tolkien (≈0.042 ms encrypt, ≈0.041 ms decrypt vs ≈0.047 ms for HRSS
  encaps) because `EES443EP1` is the one product-form parameter set in this
  crate: both the trapdoor $t = t_1 \cdot t_2 + t_3$ and the encrypt-side
  blinding $r = r_1 \cdot r_2 + r_3$ use the IEEE 1363.1 nonzero counts
  $df_1, df_2, df_3 = 9, 8, 5$ (each factor has $df_i$ coefficients equal
  to $+1$ and $df_i$ equal to $-1$), so each $r\cdot h$ (in encrypt) and
  each $t\cdot e$ (in decrypt) reduces to three very sparse convolutions
  plus an addition.
- `NTRU-HPS` and `NTRUEncrypt-EES` show the gap with NTT-friendly rings
  clearly: ML-KEM-512 keygen is ~44× faster than NTRU-HPS-509 keygen on
  Tolkien (0.023 ms vs 1.01 ms). The polynomial rings here are
  $\mathbb{Z}_q[x] / (x^N - 1)$ with prime $N$, which do not admit a direct
  radix-2 NTT; an in-tree two-prime Montgomery NTT at the smallest
  power-of-two length covering all parameter sets
  ($M = 2048 \geq 2 \cdot 821 - 1$) was prototyped and discarded — at
  $N \leq 821$ the length-2048 transform overhead exceeds Karatsuba's
  $O(N^{\log_2 3})$ cost. A right-sized per-$N$ NTT, Bluestein, or
  Rader-style decomposition would close more of the gap; the AVX2 reference
  C avoids the question by going to assembly.

Timing baselines for the pq-crystals reference C, which the fetch scripts
download into the gitignored `third_party/` directory (it is not vendored), are
available through:

- `scripts/bench_mlkem_ref.sh`
- `scripts/bench_mldsa_ref.sh`

These are for cross-checking and performance calibration, not for production
integration.

## Validation

- Full crate tests (`cargo test`) include ML-KEM, ML-DSA, NTRU, and
  NTRUEncrypt roundtrip/tamper checks.
- ML-KEM and ML-DSA are pinned byte-for-byte, for every parameter set, to
  known-answer vectors produced by the pq-crystals reference implementations
  used as oracles (`tests/vectors/ml_kem_ref_kat.txt`,
  `tests/vectors/ml_dsa_ref_kat.txt`; each header names the reference commit,
  and `scripts/gen_pq_ref_vectors.sh` regenerates them reproducibly). These
  pin `keygen_from_seed` (public *and* private key bytes, so the secret-key
  wire layout is fixed), ML-KEM `encaps_with_randomness` (ciphertext and
  shared secret), `decaps` on both a freshly generated and an imported
  decapsulation key, the implicit-rejection output `J(z || c')` for a
  corrupted ciphertext, and ML-DSA deterministic signing (`rnd = 0^32`) over
  messages of 0, 33, and 200 bytes plus verification of each signature.
- NIST ACVP vectors from the official `usnistgov/ACVP-Server` repository add
  an independent check for every parameter set, each file carrying the exact
  URLs, commit, retrieval date and `tgId`/`tcId` of every case.
  `tests/vectors/ml_kem_acvp_fips203.txt` (commit `975de31e`) holds keyGen,
  encapsulation, valid and modified-ciphertext decapsulation (the test asserts
  `K = J(z || c)` for the modified one), and the key checks that must refuse a
  modified `H(ek)` and an out-of-range `ek`, for ML-KEM-512/768/1024;
  `tests/vectors/ml_kem_fips203_subset.txt` (commit `112690e8`) is the earlier
  ML-KEM-512 subset. `tests/vectors/ml_dsa_fips204_subset.txt` (commit
  `975de31e`) holds keyGen (public and secret key), deterministic and hedged
  sigGen, and sigVer with NIST's verdict for each of its five reasons (valid,
  modified message, commitment, `z` and hint), for ML-DSA-44/65/87. Negative
  tests also cover a flipped bit at every offset of a reference signature,
  non-canonical hint encodings on every parameter set, a signature under
  another parameter set, and context strings longer than 255 bytes.
- Specification-level tests pin the arithmetic to the standards themselves: the
  NTT tables against FIPS 203 Appendix A and FIPS 204 Appendix B, ML-KEM's
  Barrett reduction over all $2^{25}$ inputs, ML-DSA's Decompose, Power2Round,
  and CoeffFromHalfByte exhaustively against the specification's formulas, NTT
  round trips and schoolbook products, literal FIPS 204 algorithms as test
  oracles, exact rejection-bound boundaries, the 814-attempt signing cap, and
  refusal of private keys with out-of-range $s_1$ or $s_2$.
- NTRU reproduces all 100 entries of the NIST PQC round-3 KAT file for each
  parameter set byte for byte, eight sampled entries by default and the full
  sweep under `cargo test --release --lib -- ntru --ignored`. The files in
  `kat/` are unmodified copies from NIST's submission package
  (`kat/README.md` gives their source and SHA-256 digests).
- NTRUEncrypt parameter sets are checked against
  `tests/vectors/ntru_ees_sves3_reference.txt` by tests generated by the
  `define_ees_set!` macro in `ntru_ees_core.rs`. The reference implementation's
  key blobs must parse and re-encode byte-for-byte, its ciphertexts must
  decrypt, and replaying the random octets it drew must reproduce each
  ciphertext exactly. This crate's own ciphertexts and key pairs, which the
  reference implementation accepted, are pinned the same way, and
  `scripts/ees_ref_vectors/generate.sh` regenerates the file. Negative tests
  reject key blobs with a wrong tag, OID or length, set padding bits, repeated
  or overlapping private-key indices, out-of-range indices or trit octets,
  wrong weights, and a public key that fails kpv3 against the private key.

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
  Supporting Documentation* (round-3 NIST PQC submission), 2020-09-30,
  published in NIST's submission package `NTRU-Round3.zip`
  (<https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/NTRU-Round3.zip>)
  (local copy: `pubs/ntru-round3-specification.pdf`). This crate's round-3 NTRU
  implementation is written from that specification and validates against the
  package's KAT files.
- K. E. Batcher, "Sorting networks and their applications", *AFIPS Spring
  Joint Computer Conference*, 1968, pp. 307–314 (the constant-time sort in
  `Fixed_Type`).
- D. E. Knuth, *The Art of Computer Programming*, Vol. 3: *Sorting and
  Searching*, 2nd ed., Addison-Wesley, 1998, §5.3.4.
- T. Itoh and S. Tsujii, "A fast algorithm for computing multiplicative
  inverses in GF(2^m) using normal bases", *Information and Computation*
  78(3), 1988, pp. 171–177 (the addition chain behind the constant-time
  inversions in $S/2$ and $S/3$).
- R. Lidl and H. Niederreiter, *Finite Fields*, Encyclopedia of Mathematics
  and its Applications 20, Cambridge University Press, 2nd ed., 1997.
- IEEE Standards Association, *IEEE Standard Specification for Public Key
  Cryptographic Techniques Based on Hard Problems over Lattices*, IEEE Std
  1363.1-2008, 2008-08-29.
  DOI: [10.1109/IEEESTD.2009.4800404](https://doi.org/10.1109/IEEESTD.2009.4800404)
  The IEEE text itself is not held here. The NTRUEncrypt implementation follows
  its public companion, the Consortium for Efficient Embedded Security's
  *EESS #1: Implementation Aspects of NTRUEncrypt*, v3.1, 2015-09-20 (local
  copy: `pubs/eess1-v3.1.pdf`), whose section numbers the code cites, and is
  validated by interoperability with the standard authors' reference
  implementation.
- Reference code is used only as a black-box oracle for test vectors and as a
  benchmark baseline, never as a source for this crate's code. It is fetched on
  demand into a gitignored `third_party/` directory by
  `scripts/fetch_mlkem_refs.sh` and `scripts/fetch_mldsa_refs.sh`, and into a
  scratch build by `scripts/ees_ref_vectors/generate.sh` (Security Innovation's
  NTRUEncrypt at a pinned commit). None of it is vendored in the repository.
