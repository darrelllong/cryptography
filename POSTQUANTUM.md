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

![ML-KEM ops/sec radar (EPYC 7452 / i5-8259U / Cortex-A76)](assets/sweep-2026-09-23-mlkem-radar.svg)

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

![ML-DSA ops/sec radar (EPYC 7452 / i5-8259U / Cortex-A76)](assets/sweep-2026-09-23-mldsa-radar.svg)

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

![NTRU ops/sec radar (EPYC 7452 / i5-8259U / Cortex-A76)](assets/sweep-2026-09-23-ntru-radar.svg)

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
| Keygen, EPYC 7452 (ms/op) | 0.2391 | 0.1929 | 1.877 | 1.045 |
| Primary op, EPYC 7452 (ms/op) | 0.04839 encaps | 0.6872 sign | 0.1252 encaps | 0.2453 encrypt |
| Secondary op, EPYC 7452 (ms/op) | 0.06271 decaps | 0.06727 verify | 0.1401 decaps | 0.4989 decrypt |

90% CI half-widths for each entry are in the per-scheme benchmark tables
below. The four schemes are not interchangeable — KEM, signature, and
public-key encryption serve different functional roles — but several
qualitative observations are visible directly in the table at this
security tier:

- ML-DSA signing is 14.2× ML-KEM encapsulation at this tier, because of the
  rejection-sampling loop; ML-DSA verification and ML-KEM decapsulation are
  within 7% of each other on the EPYC (0.067 ms against 0.063 ms), the order
  having gone the other way on the Apple M1 of the previous sweep.
- The two NTRU-family schemes carry the smallest public keys at this tier
  (≈930 bytes), and pay for it at key generation: 1.877 ms and 1.045 ms
  against ML-KEM's 0.239 ms, because the polynomial inversion in $R_q$ does
  not benefit from an NTT.
- NTRUEncrypt at this tier costs 2.0× NTRU-HPS-677 encapsulation to encrypt
  and 3.6× its decapsulation to decrypt; the SVES-3 re-encryption check
  inside `decrypt` accounts for the bulk of that second gap.

## Benchmarks

> **These are the clean-room implementations.** The tables below are the
> 2026-09-23 sweep, the first to post-date the rewrites and conformance
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
2026-09-23 sweep, taken for 0.8.0, was driven with `PILOT_PRESET=normal
PILOT_CONFIDENCE_LEVEL=0.90 PILOT_SESSION_LIMIT=300` (10% CI half-width target,
autocorrelation tolerance 0.2, ≥ 50 rounds minimum sample size); the exact
invocations are recorded in
[`bench/sweep-2026-09-23/README.md`](bench/sweep-2026-09-23/README.md), which
is the canonical record of what each host actually ran. Note that
`scripts/bench_all_pk_full.sh` defaults `PILOT_PRESET=quick`, so a re-run
without overriding the env var would not reproduce these numbers. Each host
ran one case at a time:

- AMD EPYC 7452 (`twilight`, Linux, idle)
- Intel Core i5-8259U (`dmz`, Linux, idle)
- Arm Cortex-A76 (`darby`, Raspberry Pi 5, Linux, idle)

### ML-KEM (FIPS 203)

| Operation | EPYC 7452 ms/op | EPYC 7452 ±CI (90%) | EPYC 7452 Runs | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|
| mlkem512_keygen | 0.1508 | ±0.0008338 | 170 | 0.1903 | ±0.0007349 | 50 | 0.2696 | ±0.0001931 | 56 |
| mlkem512_encaps | 0.03544 | ±0.0002962 | 55 | 0.04297 | ±0.0002806 | 80 | 0.06037 | ±0.0001224 | 53 |
| mlkem512_decaps | 0.04574 | ±0.0003122 | 50 | 0.06612 | ±0.0002058 | 50 | 0.07534 | ±0.0001802 | 50 |
| mlkem768_keygen | 0.2391 | ±0.00149 | 620 | 0.3038 | ±0.003182 | 320 | 0.4284 | ±0.0002585 | 80 |
| mlkem768_encaps | 0.04839 | ±0.0004886 | 50 | 0.0585 | ±0.0001924 | 50 | 0.08017 | ±0.0002799 | 140 |
| mlkem768_decaps | 0.06271 | ±0.0006106 | 50 | 0.07493 | ±0.0001875 | 50 | 0.1003 | ±0.0002737 | 50 |
| mlkem1024_keygen | 0.3602 | ±0.003643 | 50 | 0.4611 | ±0.002136 | 50 | 0.6472 | ±0.0005389 | 50 |
| mlkem1024_encaps | 0.06511 | ±0.0007155 | 80 | 0.08018 | ±0.0003766 | 50 | 0.1401 | ±0.0002869 | 650 |
| mlkem1024_decaps | 0.08341 | ±0.0007845 | 80 | 0.103 | ±0.0005815 | 80 | 0.1742 | ±0.0002492 | 350 |

### ML-DSA (FIPS 204)

| Operation | EPYC 7452 ms/op | EPYC 7452 ±CI (90%) | EPYC 7452 Runs | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|
| mldsa44_keygen | 0.1071 | ±0.0005769 | 80 | 0.1497 | ±0.0001907 | 80 | 0.2159 | ±0.0003011 | 170 |
| mldsa44_sign | 0.4339 | ±0.01272 | 50 | 0.4678 | ±0.01832 | 50 | 0.7351 | ±0.0262 | 80 |
| mldsa44_verify | 0.04699 | ±0.0004004 | 50 | 0.05404 | ±0.001635 | 50 | 0.07612 | ±0.0001944 | 80 |
| mldsa65_keygen | 0.1929 | ±0.00109 | 50 | 0.2592 | ±0.001798 | 50 | 0.3832 | ±0.0005827 | 80 |
| mldsa65_sign | 0.6872 | ±0.03078 | 50 | 0.7417 | ±0.03812 | 50 | 1.137 | ±0.05826 | 50 |
| mldsa65_verify | 0.06727 | ±0.0007744 | 58 | 0.07565 | ±0.0007925 | 50 | 0.1057 | ±0.0002935 | 170 |
| mldsa87_keygen | 0.2899 | ±0.003198 | 50 | 0.4043 | ±0.002247 | 82 | 0.6105 | ±0.001038 | 50 |
| mldsa87_sign | 0.6963 | ±0.03306 | 87 | 0.7784 | ±0.04432 | 50 | 1.205 | ±0.07201 | 140 |
| mldsa87_verify | 0.09643 | ±0.0008147 | 80 | 0.1105 | ±0.0008294 | 170 | 0.1548 | ±0.0004587 | 50 |

### NTRU (NIST PQC round 3)

| Operation | EPYC 7452 ms/op | EPYC 7452 ±CI (90%) | EPYC 7452 Runs | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|
| ntruhps509_keygen | 1.938 | ±0.007551 | 50 | 1.985 | ±0.007794 | 54 | 3.687 | ±0.01718 | 51 |
| ntruhps509_encaps | 0.08845 | ±0.0005963 | 110 | 0.09892 | ±0.001453 | 50 | 0.1435 | ±0.0004002 | 111 |
| ntruhps509_decaps | 0.1328 | ±0.0008157 | 80 | 0.1476 | ±0.001305 | 50 | 0.2581 | ±0.0008863 | 50 |
| ntruhps677_keygen | 1.877 | ±0.01138 | 50 | 2.106 | ±0.01404 | 170 | 3.333 | ±0.0007429 | 50 |
| ntruhps677_encaps | 0.1252 | ±0.001254 | 142 | 0.1428 | ±0.0004527 | 290 | 0.1918 | ±0.0003838 | 51 |
| ntruhps677_decaps | 0.1401 | ±0.0008394 | 112 | 0.1725 | ±0.0004538 | 384 | 0.2592 | ±0.0003085 | 50 |
| ntruhps821_keygen | 3.292 | ±0.02593 | 50 | 3.534 | ±0.01639 | 140 | 5.996 | ±0.04383 | 88 |
| ntruhps821_encaps | 0.1639 | ±0.001484 | 50 | 0.1828 | ±0.001508 | 50 | 0.2559 | ±0.0003846 | 88 |
| ntruhps821_decaps | 0.2359 | ±0.002482 | 50 | 0.2654 | ±0.001688 | 320 | 0.4356 | ±0.001669 | 80 |
| ntruhrss701_keygen | 2.305 | ±0.03568 | 50 | 2.463 | ±0.0361 | 50 | 4.039 | ±0.004182 | 50 |
| ntruhrss701_encaps | 0.07613 | ±0.001293 | 50 | 0.0848 | ±0.0002346 | 170 | 0.1249 | ±0.0002793 | 140 |
| ntruhrss701_decaps | 0.1692 | ±0.002406 | 80 | 0.1888 | ±0.001923 | 80 | 0.3001 | ±0.000266 | 140 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation | EPYC 7452 ms/op | EPYC 7452 ±CI (90%) | EPYC 7452 Runs | i5-8259U ms/op | i5-8259U ±CI (90%) | i5-8259U Runs | Cortex-A76 ms/op | Cortex-A76 ±CI (90%) | Cortex-A76 Runs |
|---|---|---|---|---|---|---|---|---|---|
| ntruees401ep1_keygen | 0.6301 | ±0.002993 | 112 | 0.6862 | ±0.009507 | 50 | 0.8422 | ±0.001308 | 84 |
| ntruees401ep1_encrypt | 0.1399 | ±0.003794 | 110 | 0.123 | ±0.003807 | 50 | 0.1721 | ±0.004166 | 110 |
| ntruees401ep1_decrypt | 0.2184 | ±0.003044 | 116 | 0.2627 | ±0.002082 | 50 | 0.2877 | ±0.0007025 | 80 |
| ntruees443ep1_keygen | 0.6179 | ±0.003917 | 80 | 0.6431 | ±0.005997 | 140 | 0.8698 | ±0.001288 | 50 |
| ntruees443ep1_encrypt | 0.03429 | ±0.0003261 | 50 | 0.0371 | ±0.001287 | 50 | 0.04818 | ±0.0003522 | 50 |
| ntruees443ep1_decrypt | 0.05331 | ±0.000565 | 110 | 0.06381 | ±0.0007183 | 50 | 0.07583 | ±0.0004121 | 110 |
| ntruees449ep1_keygen | 0.7635 | ±0.008173 | 52 | 0.8039 | ±0.009526 | 170 | 1.049 | ±0.001323 | 80 |
| ntruees449ep1_encrypt | 0.179 | ±0.01109 | 50 | 0.1749 | ±0.0108 | 50 | 0.3283 | ±0.01846 | 110 |
| ntruees449ep1_decrypt | 0.2823 | ±0.002958 | 87 | 0.2982 | ±0.002646 | 170 | 0.4834 | ±0.004274 | 50 |
| ntruees541ep1_keygen | 0.6995 | ±0.003305 | 89 | 0.6848 | ±0.003055 | 110 | 0.9682 | ±0.001963 | 50 |
| ntruees541ep1_encrypt | 0.07183 | ±0.0008767 | 230 | 0.08018 | ±0.0003181 | 261 | 0.1372 | ±0.0005541 | 1190 |
| ntruees541ep1_decrypt | 0.1245 | ±0.001059 | 59 | 0.1767 | ±0.001055 | 50 | 0.1773 | ±0.0009429 | 140 |
| ntruees677ep1_keygen | 1.045 | ±0.004152 | 86 | 1.16 | ±0.01764 | 80 | 1.436 | ±0.002582 | 50 |
| ntruees677ep1_encrypt | 0.2453 | ±0.001862 | 80 | 0.2966 | ±0.0008333 | 147 | 0.3516 | ±0.0007137 | 170 |
| ntruees677ep1_decrypt | 0.4989 | ±0.004675 | 50 | 0.5778 | ±0.003554 | 170 | 0.6386 | ±0.002021 | 54 |
| ntruees1087ep1_keygen | 1.664 | ±0.007338 | 140 | 1.601 | ±0.01037 | 55 | 1.806 | ±0.002265 | 50 |
| ntruees1087ep1_encrypt | 0.1633 | ±0.001675 | 50 | 0.1937 | ±0.001784 | 50 | 0.2243 | ±0.001729 | 50 |
| ntruees1087ep1_decrypt | 0.3166 | ±0.002017 | 110 | 0.4014 | ±0.00271 | 50 | 0.4262 | ±0.001189 | 50 |
| ntruees1087ep2_keygen | 1.755 | ±0.007532 | 50 | 1.706 | ±0.009348 | 57 | 1.898 | ±0.002775 | 50 |
| ntruees1087ep2_encrypt | 0.2938 | ±0.002415 | 50 | 0.3466 | ±0.003217 | 50 | 0.3984 | ±0.002388 | 53 |
| ntruees1087ep2_decrypt | 0.5907 | ±0.008194 | 50 | 0.7216 | ±0.004442 | 50 | 0.7852 | ±0.001884 | 54 |
| ntruees1171ep1_keygen | 1.855 | ±0.01017 | 50 | 1.88 | ±0.009146 | 260 | 2.262 | ±0.003696 | 80 |
| ntruees1171ep1_encrypt | 0.2959 | ±0.002808 | 200 | 0.3326 | ±0.00613 | 233 | 0.5076 | ±0.00466 | 209 |
| ntruees1171ep1_decrypt | 0.5391 | ±0.004929 | 111 | 0.6731 | ±0.007716 | 51 | 0.746 | ±0.003099 | 110 |
| ntruees1499ep1_keygen | 2.756 | ±0.02302 | 110 | 2.946 | ±0.01247 | 81 | 4.252 | ±0.004143 | 50 |
| ntruees1499ep1_encrypt | 0.2701 | ±0.002626 | 50 | 0.3224 | ±0.006454 | 50 | 0.3812 | ±0.003605 | 50 |
| ntruees1499ep1_decrypt | 0.5349 | ±0.004997 | 50 | 0.5404 | ±0.003417 | 50 | 0.6977 | ±0.002565 | 110 |

## Benchmark Discussion

- `ML-KEM` scales roughly with parameter size and is stable across runs. The
  intervals are tight everywhere in this sweep: ML-KEM-768 encapsulation is
  0.04839 ms ±1.0% on the EPYC and 0.08017 ms ±0.35% on the Raspberry Pi.
- `ML-DSA` verify is consistently cheaper than sign at each level, as expected:
  by 8.7× at ML-DSA-44 on the i5, and by 7.2× at ML-DSA-87 on the EPYC.
- `ML-DSA` signing variance is driven by rejection behavior in the signer loop.
  The 2026-08-11 sweep showed it as *non-monotone absolute timings across
  parameter sets* — `mldsa65_sign` above `mldsa87_sign` on that host — which
  raised the question of whether a slow-tail draw had landed on the smaller
  sample. This sweep is monotone on all four hosts: sign costs rise with the
  parameter set everywhere, and the gap between ML-DSA-65 and ML-DSA-87 is
  narrow (0.6872 against 0.6963 ms on the EPYC, 0.7417 against 0.7784 on the
  i5, 1.137 against 1.205 on the Cortex-A76). A narrow, monotone gap across
  three machines, seven counting the previous sweep, is what the
  rejection-loop explanation predicts, and the earlier inversion is best read
  as the draw it looked like.
- `NTRU` keygen costs are dominated by the polynomial inversion in $R_q$
  (Hensel lift over the variable-time $\mathbb{F}_2[x]$ Euclidean inverse).
  Keygen is the slowest operation on every parameter set: on the EPYC it is
  14.6× HPS-509 decapsulation and 30.3× HRSS-701 encapsulation.
- `NTRU-HRSS-701` encaps is the cheapest of the NTRU-family encapsulations
  on the EPYC (0.076 ms), because HRSS encryption is a single
  trinary-by-dense convolution (the Karatsuba split amortizes well for
  sparse trinary inputs). It is still slower than every ML-KEM encapsulation
  on that host — ML-KEM-512 at 0.035 ms, ML-KEM-768 at 0.048 ms and
  ML-KEM-1024 at 0.065 ms — because the NTT-friendly ring used by ML-KEM
  remains a structural advantage that dense-trinary convolution cannot
  close. `EES443EP1` encrypt and decrypt are cheaper still (0.034 ms and
  0.053 ms against 0.076 ms for HRSS encaps) because `EES443EP1` is the one
  product-form parameter set in this
  crate: both the trapdoor $t = t_1 \cdot t_2 + t_3$ and the encrypt-side
  blinding $r = r_1 \cdot r_2 + r_3$ use the IEEE 1363.1 nonzero counts
  $df_1, df_2, df_3 = 9, 8, 5$ (each factor has $df_i$ coefficients equal
  to $+1$ and $df_i$ equal to $-1$), so each $r\cdot h$ (in encrypt) and
  each $t\cdot e$ (in decrypt) reduces to three very sparse convolutions
  plus an addition.
- `NTRU-HPS` and `NTRUEncrypt-EES` show the gap with NTT-friendly rings
  clearly: ML-KEM-512 keygen is 12.9× faster than NTRU-HPS-509 keygen on
  the EPYC (0.151 ms against 1.938 ms), and 21.5× on the Apple M1 of the
  previous sweep. The ratio was ~44× in the 2026-08-11 sweep; the clean-room
  rewrites cost ML-KEM keygen more than they cost NTRU's, which narrowed it
  without changing which side of it is which. The polynomial rings here are
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
