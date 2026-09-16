# MANUAL

This manual documents the externally usable API surface of the crate as it is
today. It is organized by task and primitive family rather than by source file.

## Imports and Safety Model

The crate has two distinct surfaces:

- root-level exports for symmetric primitives, hashes, XOFs, MACs, modes, and
  the practical DRBG
- `cryptography::vt` for public-key primitives

Public-key code lives under `cryptography::vt` intentionally. Those APIs use
variable-time bigint and elliptic-curve arithmetic and are not appropriate for
side-channel-exposed production signing or decryption services.

Typical imports look like:

```rust
use cryptography::{
    Aes256, BlockCipher, CtrDrbgAes256, Gcm, Hmac, Sha256, Sha512, Xof,
    ChaCha20,
};
use cryptography::public_key::ec_edwards::ed25519;
use cryptography::vt::{
    p256, Dh, Dsa, Ecdh, Ecdsa, Ecies, Ed25519, EdDsa, EdwardsDh,
    ElGamal, MlKem, MlKemParameterSet, Paillier, Rsa, RsaOaep, RsaPss,
    X25519, X448,
};
```

## Entropy Requirements

This crate does **not** provide an operating-system entropy source.

That is deliberate. If you use `CtrDrbgAes256`, key-generation APIs, randomized
padding, or any other randomness-dependent operation, you must supply the seed
material yourself from a high-entropy external source.
Use OS-provided entropy APIs for this (`getentropy`, `SecRandomCopyBytes`,
`getrandom`, or equivalent on your target). Do not invent your own entropy
source in application code.

What this means in practice:

- `CtrDrbgAes256` is deterministic once seeded. A bad 48-byte seed gives bad
  output forever until you reseed it correctly.
- every `generate(rng, ...)` public-key API inherits the quality of the `rng`
  you pass in
- randomized schemes such as RSA OAEP, RSA PSS, ElGamal, Paillier
  rerandomization, ECIES, ECDH key generation, ECDSA/DSA randomized signing,
  and Edwards/EC key generation all depend on caller-supplied entropy
- low-entropy seeds, repeated seeds, predictable seeds, or seeds derived from
  clocks, PIDs, usernames, or other guessable values are cryptographic
  failures, not merely quality issues

The examples in this manual use fixed seed literals because the examples are
also exercised by tests and need deterministic behavior. Those literals are
for documentation only. Production callers must replace them with real external
entropy before using any randomness-dependent API.

For concrete failure modes caused by low-entropy randomness in deployed TLS
implementations, see James P. Hughes, *BADRANDOM: The Effect and Mitigations
for Low Entropy Random Numbers in TLS* (PhD thesis, 2022). Local copy:
`pubs/hughes-2022-badrandom-the-effect-and-mitigations-for-low-entropy-random-numbers-in-tls.pdf`.

## API Conventions

The public surface follows these naming rules:

- `to_wire_bytes` / `from_wire_bytes` are compact standard encodings that do
  not carry full algorithm parameters
- `to_key_blob` / `from_key_blob` are the crate-defined schema-shaped binary
  encodings; the PEM label or XML root element names the type
- `to_raw_bytes` / `from_raw_bytes` are used where the standard representation
  is already a fixed-width raw byte string, notably `Ed25519`
- explicit caller-supplied randomness uses `*_with_nonce`
- Diffie-Hellman style APIs name the returned form explicitly:
  `agree_element`, `agree_x_coordinate`, `agree_compressed_point`

## Memory wiping

This crate scrubs its own secrets in every build: key schedules and DRBG state
on drop, caller key buffers in the `*_wiping` constructors, and secret
temporaries such as speculative AEAD plaintext, KDF inputs, nonce material, and
serialized private-key bytes, all through `zeroize_slice`.

Big integers come from the sibling `rump` crate, which is general-purpose and
keeps its limb wiping off by default because wiping costs speed. This crate
turns it on, so every `BigUint` wipes its limbs on drop. Cargo feature
unification means that any build including this crate wipes every rump value.

## CSPRNG

### Root-level practical DRBG

The practical generator is `CtrDrbg<C>`, SP 800-90A Rev. 1 CTR_DRBG over
AES-256, exported at the crate root under two aliases: `CtrDrbgAes256`
(`CtrDrbg<Aes256>`, the T-table AES, variable-time) and `CtrDrbgAes256Ct`
(`CtrDrbg<Aes256Ct>`, the constant-time AES). They produce identical output
from identical inputs; choose the `Ct` alias wherever the DRBG key must not
leak through the cache. Either is a DRBG, not an entropy source.

Key methods:

- `CtrDrbgAes256::new(&[u8; 48])`
- `CtrDrbgAes256::new_wiping(&mut [u8; 48])`
- `CtrDrbgAes256::instantiate(&[u8; 48], personalization_string)` (SP 800-90A
  §10.2.1.3.1 steps 1-3: the string, at most 48 bytes, is zero-padded and XORed
  into the entropy input)
- `reseed_with_additional_input(&[u8; 48], additional_input)` (§10.2.1.4.1
  steps 1-3, the same shape)
- `reseed(&[u8; 48])`
- `reseed_wiping(&mut [u8; 48])`
- `generate(&mut [u8], Option<&[u8]>)`: additional input of up to 48 bytes,
  zero-padded to the seed length as SP 800-90A §10.2.1.5.1 step 2 requires;
  `None` and an empty slice are the no-input case
- `fill_bytes(&mut [u8])` via the `Csprng` trait
- `next_u64()` via the `Csprng` trait

Example:

```rust
use cryptography::{Csprng, CtrDrbgAes256};

// Fixed seed for a reproducible example only.
// Production code must replace this with high-entropy external seed material.
let mut seed = [0x42u8; 48];
let mut rng = CtrDrbgAes256::new_wiping(&mut seed);

let mut key = [0u8; 32];
rng.fill_bytes(&mut key);

let counter = rng.next_u64();
assert_ne!(counter, 0);
```

### Entropy checklist

Before using `CtrDrbgAes256` or any public-key `generate(...)` API, make sure:

- the seed came from a real external entropy source
- the seed is not reused across machines, users, or runs
- test/example literals never survive into deployment code
- any reseed path is held to the same entropy standard as the initial seed

## Hash, XOF, and MAC

### Fixed-output hashes

The crate exports:

- `Md5`
- `Ripemd160`
- `Sha1`
- `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`
- `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`

All fixed-output hashes support:

- `new()`
- `update(&[u8])`
- `finalize()` and `finalize_into(&mut [u8])`
- `finalize_reset()`: the digest, after which the hasher is scrubbed and
  reset to a fresh instance
- `digest(&[u8])`
- `zeroize()`

One-shot example:

```rust
use cryptography::Sha256;

let digest = Sha256::digest(b"hello");
assert_eq!(digest.len(), 32);
```

Incremental example:

```rust
use cryptography::Sha512;

let mut h = Sha512::new();
h.update(b"hello ");
h.update(b"world");
let digest = h.finalize();
assert_eq!(digest.len(), 64);
```

### XOFs

The XOF exports are:

- `Shake128`
- `Shake256`

They implement the `Xof` trait:

- `update(&[u8])`
- `squeeze(&mut [u8])`

Example:

```rust
use cryptography::{Shake256, Xof};

let mut xof = Shake256::new();
xof.update(b"context");
xof.update(b"message");

let mut out = [0u8; 64];
xof.squeeze(&mut out);
assert!(out.iter().any(|&b| b != 0));
```

### HMAC

`Hmac<H>` is exported at the crate root and works with any in-tree `Digest`.

Key methods:

- `Hmac::<H>::new(key)`
- `update(data)`
- `finalize()`
- `compute(key, data)`
- `verify(key, data, tag)`

Example:

```rust
use cryptography::{Hmac, Sha256};

let tag = Hmac::<Sha256>::compute(b"secret", b"message");
assert!(Hmac::<Sha256>::verify(b"secret", b"message", &tag));
```

### HKDF

`Hkdf<H>` implements RFC 5869 extract+expand over any in-tree `Digest`.

Key methods:

- `Hkdf::<H>::extract(salt, ikm)`
- `Hkdf::<H>::from_prk(prk)`
- `expand(info, out)`
- `derive(salt, ikm, info, len)`

Example:

```rust
use cryptography::{Hkdf, Sha256};

let hkdf = Hkdf::<Sha256>::extract(Some(b"salt"), b"input keying material");
let mut okm = [0u8; 32];
assert!(hkdf.expand(b"context", &mut okm));
```

### Block-cipher MACs

The mode layer also exports:

- `Cmac<C>`
- `Gmac<C>`
- `GmacVt<C>`

Example:

```rust
use cryptography::{Aes256, Gmac};

let gmac = Gmac::new(Aes256::new(&[0u8; 32]));
let tag = gmac.compute(&[0u8; 12], b"aad");
assert!(gmac.verify(&[0u8; 12], b"aad", &tag));
```

## Symmetric

### Block ciphers

All block ciphers implement:

```rust
pub trait BlockCipher {
    const BLOCK_LEN: usize;
    fn encrypt(&self, block: &mut [u8]);
    fn decrypt(&self, block: &mut [u8]);
}
```

Most concrete block ciphers also expose:

- `new(&[u8; N])`
- `encrypt_block(&[u8; BLOCK]) -> [u8; BLOCK]`
- `decrypt_block(&[u8; BLOCK]) -> [u8; BLOCK]`

Families exported at the crate root:

- AES: `Aes128`, `Aes192`, `Aes256`, `Aes128Ct`, `Aes192Ct`, `Aes256Ct`
- Camellia: `Camellia128`, `Camellia192`, `Camellia256`, plus `Ct` variants
- CAST: `Cast128`, `Cast128Ct`, `Cast5`, `Cast5Ct`
- DES: `Des`, `DesCt`, `TripleDes`, `TripleDesCt`
- Grasshopper: `Grasshopper`, `GrasshopperCt`
- Magma: `Magma`, `MagmaCt`
- PRESENT: `Present80`, `Present128`, and `Ct` variants
- SEED: `Seed`, `SeedCt`
- Serpent: `Serpent128`, `Serpent192`, `Serpent256` (the `Ct` names are
  aliases: the bitsliced round function is constant-time by construction);
  keys and blocks in the little-endian word order of the Serpent paper, the
  order the NESSIE vectors and deployed libraries use
- SIMON and SPECK parameter sets
- SM4: `Sm4`, `Sm4Ct`
- Twofish: `Twofish128`, `Twofish192`, `Twofish256`, plus `Ct` variants

Simple block example:

```rust
use cryptography::Aes256;

let cipher = Aes256::new(&[0u8; 32]);
let block = cipher.encrypt_block(&[0u8; 16]);
let roundtrip = cipher.decrypt_block(&block);
assert_eq!(roundtrip, [0u8; 16]);
```

### Modes

The mode layer exports:

- `Ecb<C>`
- `Cbc<C>`
- `Cfb<C>`
- `Cfb8<C>`
- `Ofb<C>`
- `Ctr<C>`
- `Xts<C>`
- `Cmac<C>`
- `Ccm<C>`
- `Gcm<C>`
- `GcmVt<C>`
- `Gmac<C>`
- `GmacVt<C>`
- `AesKeyWrap<C>`
- `Eax<C>`
- `Ocb<C, TAG_LEN>`
- `Siv<C>` (RFC 5297: at most `MAX_PLAINTEXT_BYTES` = 2^36 − 16 bytes per
  message and `MAX_AD_COMPONENTS` = 126 associated-data components;
  `encrypt(nonce, aad, p)` forms the S2V vector `[aad, nonce]`, or `[aad]`
  when the nonce is empty; `decrypt` returns `false` beyond either bound)
- `AesGcmSiv<C>` (`C: GcmSivBlockCipher`), as `Aes128GcmSiv`, `Aes256GcmSiv`
  on the T-table AES and `Aes128GcmSivCt`, `Aes256GcmSivCt` on the
  constant-time AES
- `Poly1305`
- `ChaCha20Poly1305`

Constructor pattern:

- `Mode::new(cipher)`

Representative methods:

- `encrypt_nopad` / `decrypt_nopad` for `Ecb`, `Cbc`, `Cfb`
- `encrypt` / `decrypt` for `Cfb8`
- `apply_keystream` for `Ofb`, `Ctr`
- `encrypt_sector` / `decrypt_sector` for `Xts`
- `encrypt` / `decrypt` / `compute_tag` for `Ccm`
- `encrypt`, `decrypt`, `compute_tag` for `Gcm` and `GcmVt`
- `wrap_key` / `unwrap_key` for `AesKeyWrap` (RFC 3394, no padding)
- `encrypt` / `decrypt` for `Eax`, `Ocb`, and `Siv`
- `encrypt` / `decrypt` for `AesGcmSiv<C>` and its four aliases
- `compute` / `verify` for `Poly1305`
- `encrypt`, `decrypt`, `encrypt_in_place`, `decrypt_in_place` for
  `ChaCha20Poly1305`

`Ocb<C, TAG_LEN>` takes the RFC 7253 tag length in bytes as a const generic:
16 (the default, TAGLEN 128), 12 (TAGLEN 96), or 8 (TAGLEN 64), the
`AEAD_AES_*_OCB_TAGLEN128/96/64` parameter sets of RFC 7253 section 3.1. Any
other length fails to compile. TAGLEN is folded into OCB's nonce block, so a
96-bit tag is not a truncated 128-bit tag. `Ocb<C>` names the 128-bit mode;
when nothing else fixes the tag type, give the length at construction:

```rust
use cryptography::{Aes128, Ocb};

let ocb = Ocb::<_, 12>::new(Aes128::new(&[0u8; 16])); // AEAD_AES_128_OCB_TAGLEN96
let nonce = [1u8; 12];
let mut data = b"ocb payload".to_vec();
let tag: [u8; 12] = ocb.encrypt(&nonce, b"header", &mut data);
assert!(ocb.decrypt(&nonce, b"header", &mut data, &tag));
assert_eq!(data, b"ocb payload");
```

`Gcm` and `Gmac` are the safe-default constant-time GHASH-backed variants.
`GcmVt` and `GmacVt` are the explicit variable-time reference/performance
variants.
`Aead` is the shared detached-tag trait implemented by `Gcm`, `GcmVt`, `Ccm`,
`Eax`, `Ocb`, `Siv`, `AesGcmSiv<C>`, and `ChaCha20Poly1305`.
`Gcm` and `GcmVt` enforce the SP 800-38D per-call payload bound of
$(2^{32}-2)$ counter blocks (`68_719_476_704` bytes); oversized inputs panic
to prevent counter wrap.

Example: AES-256-GCM

```rust
use cryptography::{Aes256, Gcm};

let gcm = Gcm::new(Aes256::new(&[0u8; 32]));
let nonce = [0u8; 12];
let aad = b"header";
let mut data = b"secret message".to_vec();

let tag = gcm.encrypt(&nonce, aad, &mut data);
assert!(gcm.decrypt(&nonce, aad, &mut data, &tag));
assert_eq!(data, b"secret message");
```

Example: CTR mode over AES

```rust
use cryptography::{Aes128, Ctr};

let ctr = Ctr::new(Aes128::new(&[0u8; 16]));
let counter = [0u8; 16];
let mut buf = b"plaintext".to_vec();
ctr.apply_keystream(&counter, &mut buf);
ctr.apply_keystream(&counter, &mut buf);
assert_eq!(buf, b"plaintext");
```

Example: ChaCha20-Poly1305 AEAD

```rust
use cryptography::ChaCha20Poly1305;

let aead = ChaCha20Poly1305::new(&[0u8; 32]);
let nonce = [0u8; 12];
let aad = b"header";
let (ct, tag) = aead.encrypt(&nonce, aad, b"secret message");
assert_eq!(
    aead.decrypt(&nonce, aad, &ct, &tag),
    Some(b"secret message".to_vec())
);
```

### Worked example: `encrypt_file` / `decrypt_file` with counter mode

This is a minimal complete file-encryption example built directly from the
surface API.

Important caveat: `CTR` mode gives confidentiality only. It does **not**
authenticate the ciphertext. In real deployments, pair this with a MAC or use
`Gcm<Aes256>` instead unless a separate integrity layer already exists.

```rust,no_run
use std::fs;
use std::path::Path;

use cryptography::{Aes256, Ctr};

fn encrypt_file(input: &Path, output: &Path, key: &[u8; 32], counter: &[u8; 16]) {
    let ctr = Ctr::new(Aes256::new(key));
    let mut data = fs::read(input).expect("read plaintext");
    ctr.apply_keystream(counter, &mut data);
    fs::write(output, data).expect("write ciphertext");
}

fn decrypt_file(input: &Path, output: &Path, key: &[u8; 32], counter: &[u8; 16]) {
    let ctr = Ctr::new(Aes256::new(key));
    let mut data = fs::read(input).expect("read ciphertext");
    ctr.apply_keystream(counter, &mut data);
    fs::write(output, data).expect("write plaintext");
}

// Round-trip usage.
let key = [0x11u8; 32];
let counter = [0x22u8; 16];

encrypt_file(
    Path::new("plain.txt"),
    Path::new("secret.bin"),
    &key,
    &counter,
);
decrypt_file(
    Path::new("secret.bin"),
    Path::new("roundtrip.txt"),
    &key,
    &counter,
);
```

### Stream ciphers

The stream ciphers are byte-oriented inherent APIs rather than `BlockCipher`
implementations.

Shared trait:

- `StreamCipher` with `fill(&mut [u8])` and `apply_keystream(&mut [u8])`

Root-level exports:

- `ChaCha20`
- `XChaCha20`
- `Salsa20`
- `Rabbit`
- `Snow3g`, `Snow3gCt`
- `Zuc128`, `Zuc128Ct`

`Snow3g` and `Zuc128` index their S-box and multiplier tables with secret
bytes; use `Snow3gCt` and `Zuc128Ct` wherever timing or cache behaviour is
observable.

Common method pattern:

- `new(key, nonce_or_iv)`
- `apply_keystream(&mut [u8])`
- `fill(&mut [u8])`

Some stream ciphers also expose:

- `with_counter(...)` and `set_counter(...)` for ChaCha20, XChaCha20 and
  Salsa20
- `with_key_bytes(...)` for Salsa20 (16- or 32-byte keys)
- `without_iv(...)` for Rabbit (RFC 4503 §3.2: never reset under the same key)
- `keystream_block()` for ChaCha20, XChaCha20, Salsa20 and Rabbit

Example: ChaCha20

```rust
use cryptography::ChaCha20;

let mut cipher = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
let mut buf = b"stream data".to_vec();
let original = buf.clone();

cipher.apply_keystream(&mut buf);

let mut cipher = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
cipher.apply_keystream(&mut buf);
assert_eq!(buf, original);
```

Example: SNOW 3G

```rust
use cryptography::Snow3gCt;

let mut snow = Snow3gCt::new(&[0u8; 16], &[0u8; 16]);
let mut stream = [0u8; 64];
snow.fill(&mut stream);
assert!(stream.iter().any(|&b| b != 0));
```

## Public-Key

All public-key APIs live under `cryptography::vt`.

```rust
use cryptography::public_key::ec_edwards::ed25519;
use cryptography::vt::{p256, Ecdsa, Ed25519, Rsa};
```

The public-key surface naturally splits into:

- finite-field / integer schemes
- short-Weierstrass EC schemes
- Edwards-curve schemes

### Serialization rules

Public-key serialization is not uniform across all families:

- RSA uses standard PKCS/SPKI methods such as `to_pkcs8_der()` and
  `to_spki_pem()`
- most non-RSA key types use `to_key_blob()` / `from_key_blob()` for the
  crate-defined binary format
- EC and Edwards public keys that have compact standard point encodings expose
  `to_wire_bytes()` / `from_wire_bytes(...)`
- `Ed25519` uses `to_raw_bytes()` / `from_raw_bytes()` for its standard 32-byte
  forms

PEM and XML wrappers are available on most key types:

- `to_pem()` / `from_pem(...)`
- `to_xml()` / `from_xml(...)`

### Standard key encodings

The crate-defined formats above stay the defaults: `to_key_blob`, `to_pem`
and `to_xml` keep their exact behaviour. Beside them, every key type with a
published PKIX encoding has explicitly named methods for it, in DER and in RFC
7468 PEM, each with a matching `from_*` decoder:

| Family | Public key | Private key | Domain parameters |
|---|---|---|---|
| RSA | `to_spki_der` / `to_spki_pem` (RFC 3279 §2.3.1); `to_pkcs1_der` / `to_pkcs1_pem` | `to_pkcs8_der` / `to_pkcs8_pem` (RFC 5958); `to_pkcs1_der` / `to_pkcs1_pem` | — |
| ECDSA, ECDH, ECIES | `to_spki_der` / `to_spki_pem` (RFC 5480) | `to_pkcs8_der` / `to_pkcs8_pem` (RFC 5958 holding RFC 5915); `to_sec1_der` / `to_sec1_pem` (RFC 5915 `EC PRIVATE KEY`) | — |
| DSA | `to_spki_der` / `to_spki_pem` (RFC 3279 §2.3.2) | `to_pkcs8_der` / `to_pkcs8_pem` (RFC 5958 §2) | `DsaParams::to_der` (`Dss-Parms`) |
| DH | `to_spki_der` / `to_spki_pem` (RFC 3279 §2.3.3) | `to_pkcs8_der` / `to_pkcs8_pem` (no standard; OpenSSL's convention) | `DhParams::to_der` (X9.42 `DomainParameters`) |
| X25519, X448, Ed25519 | `to_spki_der` / `to_spki_pem` (RFC 8410 §4) | `to_pkcs8_der` / `to_pkcs8_pem` (RFC 8410 §7) | — |
| ML-KEM | `to_spki_der` / `to_spki_pem` (RFC 9935) | `to_pkcs8_der` / `to_pkcs8_pem` (RFC 9935: seed, expanded key, or both) | — |
| ML-DSA | `to_spki_der` / `to_spki_pem` (RFC 9881) | `to_pkcs8_der` / `to_pkcs8_pem` (RFC 9881: seed, expanded key, or both) | — |

- An elliptic-curve key has a standard encoding only on a curve with an object
  identifier (RFC 5480 §2.1.1.1 for the NIST curves, SEC 2 §A.2.1 for
  secp256k1): `p192`, `p224`, `p256`, `p384`, `p521`, `secp256k1` and the ten
  binary curves. On any other curve the EC `to_*` methods return `None`, and
  the decoders reject a curve identifier they do not know. Points are written
  uncompressed and accepted in either form; the ECDH decoders also accept
  RFC 5480's `id-ecDH`.
- No published standard defines a Diffie-Hellman private key inside PKCS #8.
  `DhPrivateKey::to_pkcs8_der` follows the convention OpenSSL writes and reads
  (`dhpublicnumber`, the `DomainParameters`, and `x` as an `INTEGER`), and its
  documentation says so.
- `DhParams::to_der` writes a FIPS 186-4 seed and counter as
  `ValidationParms`. That structure has no room for the hash function and
  index a FIPS 186-4 validator needs, so `DhParams::from_der` checks its shape
  and returns parameters without a seed record.
- An ML-KEM or ML-DSA private key is written as its seed when it was generated
  from or read with one, the form RFC 9935 and RFC 9881 recommend, and as the
  FIPS expanded key otherwise. All three forms are read, with the RFCs'
  consistency checks. The crate has no Ed448 signatures, so RFC 8410's Ed448
  identifier is not used.
- Every `_der` decoder accepts strict X.690 DER with no trailing bytes. Where
  an RFC asks receivers to accept BER, any X.690 BER encoding is accepted:
  `from_pkcs8_ber` on every private-key type (RFC 5958 §2), `from_sec1_ber` on
  EC private keys (RFC 5915 §4), and the `PRIVATE KEY` and `PUBLIC KEY` PEM
  decoders of every key type (RFC 7468 §10 and §13). Contents an algorithm's
  RFC requires in DER, such as an RSA or DSA public key or an ML-KEM or ML-DSA
  private-key `CHOICE`, stay DER inside a BER container. PEM is read by RFC
  7468 §2's parser rules: text before the boundary is ignored, CRLF, CR and LF
  all end lines, whitespace and other non-base64 characters between the
  boundaries are ignored, and the base64 must be canonical.
- A decoded key is validated as the crate-defined parsers validate it: private
  keys completely and public keys structurally. EC points must be on the
  curve, in the prime-order subgroup and not the identity (SEC 1 §3.2.2.1).
  Ed25519 points are decoded exactly as RFC 8032 §5.1.3 allows, so small-order
  Ed25519 keys are accepted.

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::{p256, Ecdsa, EcdsaPrivateKey, EcdsaPublicKey};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[0x31; 48]);
let (public, private) = Ecdsa::generate(p256(), &mut rng);

// `None` only for a curve without an object identifier.
let spki_pem = public.to_spki_pem().expect("P-256 is a named curve");
let pkcs8_pem = private.to_pkcs8_pem().expect("P-256 is a named curve");

let public_again = EcdsaPublicKey::from_spki_pem(&spki_pem).expect("SPKI");
let private_again = EcdsaPrivateKey::from_pkcs8_pem(&pkcs8_pem).expect("PKCS #8");
assert_eq!(public_again.public_point(), public.public_point());
assert_eq!(private_again.private_scalar(), private.private_scalar());
```

### Finite-field and integer schemes

Primary root types:

- `Rsa`
- `RsaOaep<H>`
- `RsaPss<H>`
- `Dh`
- `Dsa`
- `ElGamal`
- `Paillier`
- `Rabin`
- `SchmidtSamoa`
- `Cocks`

#### RSA

Key-generation methods:

- `Rsa::generate(rng, bits)` — FIPS 186-4 B.3.3 random probable primes with
  `e = 65537`; `bits` even and at least 32; the modulus is exactly `bits` long
- `Rsa::generate_with_exponent(rng, bits, e)`
- `Rsa::from_primes(...)`
- `Rsa::from_primes_with_exponent(...)`

Raw operations:

- `RsaPublicKey::encrypt_raw(&BigUint) -> BigUint`
- `RsaPrivateKey::decrypt_raw(&BigUint) -> BigUint`

Standards-based wrappers:

- `RsaOaep::<H>::encrypt(public, label, message)`
- `RsaOaep::<H>::encrypt_rng(public, label, message, rng)`
- `RsaOaep::<H>::decrypt(private, label, ciphertext)`
- `RsaOaep::<H>::decrypt_rng(private, label, ciphertext, rng)` — the blinded
  private operation; prefer it when a CSPRNG is available
- `RsaPss::<H>::sign(private, message, salt)`
- `RsaPss::<H>::sign_rng(private, message, salt_len, rng)`
- `RsaPss::<H>::verify(public, message, signature, salt_len)` — `salt_len` is
  RFC 8017's `sLen`; a signature made with another salt length does not verify

RSA serialization:

- public: `to_pkcs1_der`, `to_spki_der`, `to_pkcs1_pem`, `to_spki_pem`
- private: `to_pkcs1_der`, `to_pkcs8_der`, `to_pkcs1_pem`, `to_pkcs8_pem`

Example: RSA OAEP and PSS

```rust
use cryptography::{CtrDrbgAes256, Sha256, Sha512};
use cryptography::vt::{Rsa, RsaOaep, RsaPss};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[7u8; 48]);
let (public, private) = Rsa::generate(&mut rng, 1024).expect("rsa");

let ciphertext = RsaOaep::<Sha256>::encrypt_rng(&public, b"label", b"hello", &mut rng)
    .expect("oaep encrypt");
let plaintext = RsaOaep::<Sha256>::decrypt_rng(&private, b"label", &ciphertext, &mut rng)
    .expect("oaep decrypt");
assert_eq!(plaintext, b"hello");

// RFC 8017 §9.1.1 step 3 needs emLen ≥ hLen + sLen + 2: with a 1024-bit
// modulus (emLen = 128) and SHA-512 (hLen = 64), the salt is at most 62 bytes.
let signature = RsaPss::<Sha512>::sign_rng(&private, b"hello", 32, &mut rng)
    .expect("pss sign");
assert!(RsaPss::<Sha512>::verify(&public, b"hello", &signature, 32));
```

#### Diffie-Hellman over finite fields

Key types:

- `DhParams`
- `DhPublicKey`
- `DhPrivateKey`

Generation:

- `Dh::generate_params(rng, size, hash)`: FIPS 186-4 domain parameters, with
  their seed record, at SP 800-56A's sizes FB `(2048, 224)` and FC
  `(2048, 256)`; `None` for other sizes or a hash shorter than `N`
- `Dh::generate_toy_params(rng, bits)`: groups below 1024 bits for tests,
  following no standard
- `Dh::generate(&params, rng)`

Third-party parameters:

- `DhParams::new(p, q, g)`: hardened primality and subgroup structure
- `DhParams::with_seed(p, q, g, FfcSeed::new(hash, seed, counter, index))`:
  FIPS 186-4 A.1.1.3 and A.2.4

Agreement:

- `DhPrivateKey::agree_element(&peer) -> Option<BigUint>`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::public_key::primes::{FfcHash, FfcParameterSize};
use cryptography::vt::Dh;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[9u8; 48]);
let params = Dh::generate_params(&mut rng, FfcParameterSize::L2048N224, FfcHash::Sha224)
    .expect("params");
let (pub_a, priv_a) = Dh::generate(&params, &mut rng);
let (pub_b, priv_b) = Dh::generate(&params, &mut rng);

let shared_a = priv_a.agree_element(&pub_b).expect("agree a");
let shared_b = priv_b.agree_element(&pub_a).expect("agree b");
assert_eq!(shared_a, shared_b);
```

#### DSA

Generation:

- `Dsa::generate_params(rng, size, hash)`: FIPS 186-4 A.1.1.2 and A.2.3 at a
  §4.2 `(L, N)` pair, keeping the seed record; `None` for a hash shorter than
  `N`
- `Dsa::generate_toy_params(rng, bits)`: groups below 1024 bits for tests,
  following no standard
- `Dsa::generate(&params, rng)`
- `Dsa::from_secret_exponent(...)`
- `DsaParams::new(p, q, g)` and `DsaParams::with_seed(p, q, g, seed)` for
  third-party parameters (the latter by FIPS 186-4 A.1.1.3 and A.2.4)

Signing and verification:

- `sign_message::<H>(message)`
- `sign_message_with_rng::<H, R>(message, rng)`
- `sign_digest::<H>(digest)`
- `sign_digest_with_rng(digest, rng)`
- `sign_digest_with_nonce(digest, nonce)`
- `verify_message::<H>(message, signature)`
- `verify_message_bytes::<H>(message, signature_bytes)`
- `verify(digest, signature)`
- `verify_digest_scalar(&BigUint, signature)`

`sign_digest` and `sign_message` derive the nonce by RFC 6979, which FIPS
186-4 does not approve; the `_with_rng` forms draw it at random as FIPS 186-4
Appendix B.2 does.

Example:

```rust
use cryptography::{CtrDrbgAes256, Sha256};
use cryptography::public_key::primes::{FfcHash, FfcParameterSize};
use cryptography::vt::Dsa;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[3u8; 48]);
let params = Dsa::generate_params(&mut rng, FfcParameterSize::L2048N256, FfcHash::Sha256)
    .expect("params");
let (public, private) = Dsa::generate(&params, &mut rng);

let sig = private.sign_message::<Sha256>(b"message").expect("sign");
assert!(public.verify_message::<Sha256>(b"message", &sig));
```

#### ElGamal, Paillier, and the educational schemes

Normal APIs:

- `ElGamalPublicKey::encrypt(...)`
- `ElGamalPublicKey::encrypt_with_nonce(...)`
- `ElGamalPrivateKey::decrypt(...)` (`Option`: the ciphertext components are
  validated against the group before any exponentiation)
- `PaillierPublicKey::encrypt(...)`
- `PaillierPublicKey::encrypt_with_nonce(...)`
- `PaillierPrivateKey::decrypt(...)`
- `PaillierPublicKey::add_ciphertexts(...)`
- `Rabin`, `SchmidtSamoa`, `Cocks` expose `encrypt_raw` plus byte wrappers

Example: Paillier homomorphic addition

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::{BigUint, Paillier};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[5u8; 48]);
let (public, private) = Paillier::generate(&mut rng, 256).expect("paillier");

let c1 = public.encrypt_with_nonce(&BigUint::from_u64(10), &BigUint::from_u64(3))
    .expect("enc1");
let c2 = public.encrypt_with_nonce(&BigUint::from_u64(20), &BigUint::from_u64(5))
    .expect("enc2");
let sum_ct = public.add_ciphertexts(&c1, &c2).expect("add");
let sum = private.decrypt_raw(&sum_ct).expect("ciphertext below n²");
assert_eq!(sum, BigUint::from_u64(30));
```

### Short-Weierstrass EC

Every elliptic-curve public-key import (wire bytes, key blob, PEM, XML and
SPKI) applies SEC 1 v2.0 §3.2.2.1 public-key validation: coordinates in
range, the point on the curve and in the prime-order subgroup, and never the
identity. Private-key imports require 1 ≤ d < n and a valid public point d·G,
and ECDSA verification refuses the identity as well.

Curve constructors exported from `cryptography::vt`:

- prime-field curves: `p192`, `p224`, `p256`, `p384`, `p521`, `secp256k1`
- binary curves: `b163`, `k163`, `b233`, `k233`, `b283`, `k283`, `b409`,
  `k409`, `b571`, `k571`

Typed schemes:

- `Ecdh`
- `Ecdsa`
- `Ecies`
- `EcElGamal`

Low-level arithmetic is available through:

- `CurveParams`
- `AffinePoint`

#### ECDH

Generation, import, and agreement:

- `Ecdh::generate(curve, rng)`
- `Ecdh::from_secret_scalar(curve, d) -> Option<(EcdhPublicKey, EcdhPrivateKey)>`
- `EcdhPrivateKey::agree_x_coordinate(&peer) -> Option<Vec<u8>>`

Public-key encoding:

- `EcdhPublicKey::to_wire_bytes()`
- `EcdhPublicKey::from_wire_bytes(curve, bytes)`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::{p256, Ecdh};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[1u8; 48]);
let (pub_a, priv_a) = Ecdh::generate(p256(), &mut rng);
let (pub_b, priv_b) = Ecdh::generate(p256(), &mut rng);

let shared_a = priv_a.agree_x_coordinate(&pub_b).expect("a");
let shared_b = priv_b.agree_x_coordinate(&pub_a).expect("b");
assert_eq!(shared_a, shared_b);
```

`Ecdh::from_secret_scalar` imports a private scalar fixed outside the crate,
such as a published test vector or another implementation's key. It returns
`None` unless `1 <= d < n`, the contract of `Ecdsa::from_secret_scalar`:

```rust
use cryptography::vt::{p256, BigUint, Ecdh};

let curve = p256();
let d = BigUint::from_u64(7);
let (public, private) = Ecdh::from_secret_scalar(curve.clone(), &d).expect("1 <= d < n");
assert_eq!(private.private_scalar(), &d);
assert_eq!(public.public_point(), &curve.scalar_mul(&curve.base_point(), &d));
assert!(Ecdh::from_secret_scalar(curve, &BigUint::zero()).is_none());
```

#### ECDSA

Generation:

- `Ecdsa::generate(curve, rng)`
- `Ecdsa::from_secret_scalar(curve, d)`

Signing and verification:

- `sign_message::<H>(message)`
- `sign_message_with_rng::<H, R>(message, rng)`
- `sign_digest::<H>(digest)`
- `sign_digest_with_rng(digest, rng)`
- `sign_digest_with_nonce(digest, nonce)`
- `verify_message::<H>(message, signature)`
- `verify(digest, signature)`
- `verify_digest_scalar(&BigUint, signature)`

Signing emits `s` as FIPS 186-5 §6.4.1 computes it;
`EcdsaSignature::to_low_s(curve)` gives the `s ≤ n/2` form protocols that
forbid malleability require. Verification accepts any `1 ≤ s < n`, so
signatures from OpenSSL and other implementations verify whether or not they
are canonical. Empty digests are refused by signing and verification.

Wire encoding for public keys and signatures:

- `EcdsaPublicKey::to_wire_bytes()`
- `EcdsaPublicKey::from_wire_bytes(curve, bytes)`
- `EcdsaSignature::to_der()` / `EcdsaSignature::from_der(bytes)` — the
  X9.62 / RFC 3279 §2.2.3 `ECDSA-Sig-Value`

Example:

```rust
use cryptography::{CtrDrbgAes256, Sha256};
use cryptography::vt::{p256, Ecdsa};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[2u8; 48]);
let (public, private) = Ecdsa::generate(p256(), &mut rng);

let sig = private.sign_message::<Sha256>(b"ecdsa message").expect("sign");
assert!(public.verify_message::<Sha256>(b"ecdsa message", &sig));
```

#### ECIES

SEC 1 v2.0 §5.1 ECIES. SEC 1 makes it a family of schemes: the recipient picks
a key derivation function, a MAC scheme, a symmetric encryption scheme,
standard or cofactor Diffie–Hellman, and point compression, and the sender
must use the same choices. `EciesSetup` carries all five and both operations
take it; nothing is defaulted.

Generation:

- `Ecies::generate(curve, rng)`

Scheme setup (`cryptography::public_key::ecies`):

- `EciesSetup::RECOMMENDED`: ANSI-X9.63-KDF with SHA-256, AES-128-CTR,
  HMAC-SHA-256-256, cofactor Diffie–Hellman, uncompressed `R`
- `EciesSetup::new(kdf, encryption, mac, dh_primitive, point_format)`
- `EciesKdf::AnsiX963(EciesHash::{Sha1, Sha224, Sha256, Sha384, Sha512})`
- `EciesEncryption::{Xor, XorBackwardsCompatible, TdesCbc, Aes128Cbc,
  Aes192Cbc, Aes256Cbc, Aes128Ctr, Aes192Ctr, Aes256Ctr}`
- `EciesMac::{HmacSha1_160, HmacSha1_80, HmacSha224_112, HmacSha224_224,
  HmacSha256_128, HmacSha256_256, HmacSha384_192, HmacSha384_384,
  HmacSha512_256, HmacSha512_512, CmacAes128, CmacAes192, CmacAes256}`
- `EciesDhPrimitive::{Standard, Cofactor}`,
  `EciesPointFormat::{Uncompressed, Compressed}`

Hybrid encryption (SharedInfo₁ feeds the KDF and SharedInfo₂ the MAC; pass
`&[]` when absent):

- `EciesPublicKey::encrypt(setup, message, shared_info1, shared_info2, rng) -> Result<Vec<u8>, EciesError>`
- `EciesPrivateKey::decrypt(setup, ciphertext, shared_info1, shared_info2) -> Option<Vec<u8>>`

The ciphertext is `R ‖ EM ‖ D`: the SEC 1 encoding of the ephemeral point, the
symmetric ciphertext (as long as the message), and the tag. The CBC schemes
take whole blocks only, because SEC 1 defines no padding. SharedInfo₂ needs a
suffix-free format, since the MAC covers `EM ‖ SharedInfo₂` with no separator.

Public-key compact form:

- `EciesPublicKey::to_wire_bytes()`
- `EciesPublicKey::from_wire_bytes(curve, bytes)`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::public_key::ecies::EciesSetup;
use cryptography::vt::{p256, Ecies};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[4u8; 48]);
let (public, private) = Ecies::generate(p256(), &mut rng);

let setup = EciesSetup::RECOMMENDED;
let ciphertext = public
    .encrypt(setup, b"ecies payload", &[], &[], &mut rng)
    .expect("encrypt");
let plaintext = private
    .decrypt(setup, &ciphertext, &[], &[])
    .expect("decrypt");
assert_eq!(plaintext, b"ecies payload");
```

#### EC-ElGamal

Generation:

- `EcElGamal::generate(curve, rng)`

Operations:

- `encrypt_point(...) -> Option<EcElGamalCiphertext>` (`None` for a
  plaintext outside the subgroup of order `n`)
- `encrypt_point_with_nonce(...) -> Option<EcElGamalCiphertext>` (also `None`
  for a nonce outside `[1, n)`)
- `encrypt(...)`
- `encrypt_int(...)`
- `decrypt_point(...)`
- `decrypt(...)`
- `decrypt_int(ciphertext, bound)`
- `add_ciphertexts(...)`

Public-key compact form:

- `EcElGamalPublicKey::to_wire_bytes()`
- `EcElGamalPublicKey::from_wire_bytes(curve, bytes)`

This is the additive-homomorphic EC ElGamal layer, not ECIES.

`decrypt_int(ciphertext, bound)` recovers an integer in `0..bound`. The bound
is exclusive, as in a Rust range: `bound - 1` is recovered and `bound` is not,
so pick a bound above the largest value a (summed) ciphertext can hold.
Recovery is a baby-step giant-step search costing `O(sqrt(bound))` time and
memory. `EdwardsElGamalPrivateKey::decrypt_int` uses the same convention. Both refuse a `bound` above `MAX_DECRYPT_INT_BOUND` (`2^40`) with `None`
before doing any work.

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::{p256, EcElGamal};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[2u8; 48]);
let (public, private) = EcElGamal::generate(p256(), &mut rng);
let sum = public.add_ciphertexts(
    &public.encrypt_int(9, &mut rng),
    &public.encrypt_int(6, &mut rng),
);
assert_eq!(private.decrypt_int(&sum, 16), Some(15));
assert_eq!(private.decrypt_int(&sum, 15), None); // the bound is exclusive
```

### Edwards curves

Built-in curve constructor:

- `cryptography::public_key::ec_edwards::ed25519() -> TwistedEdwardsCurve`

Typed schemes:

- `Ed25519`
- `EdDsa`
- `EdwardsDh`
- `EdwardsElGamal`

Low-level arithmetic:

- `TwistedEdwardsCurve`
- `EdwardsPoint`

#### Ed25519

Public keys and a signature's R are decoded exactly as RFC 8032 §5.1.3
specifies, and verification checks §5.1.7's cofactored equation
[8][S]B = [8]R + [8][k]A'. Small-order and mixed-order public keys are
accepted, as RFC 8032 accepts them. Such a key binds no secret: under a
small-order key, a signature with the neutral R and S = 0 verifies for every
message. A caller that needs a key tied to a secret should check
`is_valid_public_point` on its point.

Generation and import:

- `Ed25519::generate(rng)`
- `Ed25519::from_seed([u8; 32])`

Encodings:

- `Ed25519PublicKey::to_raw_bytes()`
- `Ed25519PublicKey::from_raw_bytes(bytes)`
- `Ed25519PrivateKey::to_raw_bytes()`
- `Ed25519PrivateKey::from_raw_bytes(bytes)`
- `Ed25519Signature::to_key_blob()`
- `Ed25519Signature::from_key_blob(bytes)`

Signing and verification:

- `Ed25519PrivateKey::sign_message(message) -> Ed25519Signature`
- `Ed25519PrivateKey::sign_message_bytes(message) -> Vec<u8>`
- `Ed25519PublicKey::verify_message(message, signature)`
- `Ed25519PublicKey::verify_message_bytes(message, signature_bytes)`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::Ed25519;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[6u8; 48]);
let (public, private) = Ed25519::generate(&mut rng);

let sig = private.sign_message(b"ed25519");
assert!(public.verify_message(b"ed25519", &sig));
```

#### Generic EdDSA over Edwards curves

Generation:

- `EdDsa::generate(curve, rng)`
- `EdDsa::from_secret_scalar(curve, d)`

Signing and verification:

- `sign_message::<H, R>(message, rng)`
- `sign_message_with_nonce::<H>(message, nonce)`
- `sign_message_bytes::<H, R>(message, rng)`
- `verify_message::<H>(message, signature)`
- `verify_message_bytes::<H>(message, signature_bytes)`

Public-key compact form:

- `EdDsaPublicKey::to_wire_bytes()`
- `EdDsaPublicKey::from_wire_bytes(curve, bytes)`

Example:

```rust
use cryptography::{CtrDrbgAes256, Sha512};
use cryptography::public_key::ec_edwards::ed25519;
use cryptography::vt::EdDsa;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[8u8; 48]);
let (public, private) = EdDsa::generate(ed25519(), &mut rng);

let sig = private.sign_message::<Sha512, _>(b"eddsa", &mut rng).expect("sign");
assert!(public.verify_message::<Sha512>(b"eddsa", &sig));
```

#### Curve25519 / Curve448 Diffie-Hellman (RFC 7748)

`X25519` and `X448` are the Montgomery-ladder ECDH primitives from RFC 7748.
Unlike the rest of `cryptography::vt`, both are constant-time in the secret
scalar: the field arithmetic uses fixed-radix limbs (5×51 for X25519, 8×56 for
X448), conditional swaps are mask-driven, and there is no data-dependent
branching or table indexing.

Functional API:

- `X25519::scalar_mult(&[u8; 32], &[u8; 32]) -> [u8; 32]`
- `X25519::scalar_mult_base(&[u8; 32]) -> [u8; 32]`
- `X25519::generate(rng) -> (X25519PublicKey, X25519PrivateKey)`
- `X448::scalar_mult(&[u8; 56], &[u8; 56]) -> [u8; 56]`
- `X448::scalar_mult_base(&[u8; 56]) -> [u8; 56]`
- `X448::generate(rng) -> (X448PublicKey, X448PrivateKey)`

Key types:

- `X25519PrivateKey` / `X25519PublicKey` (32-byte raw)
- `X448PrivateKey` / `X448PublicKey` (56-byte raw)

Both private-key types zeroise on drop and expose `from_raw_bytes` /
`to_raw_bytes` / `from_raw_bytes_wiping` / `to_public_key` / `agree`. `agree`
returns `Option<[u8; N]>` and rejects the all-zero output (low-order point)
per the conservative recommendation in RFC 7748 §6.

Example (X25519):

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::X25519;

let mut rng = CtrDrbgAes256::new(&[0x11u8; 48]);
let (pub_a, priv_a) = X25519::generate(&mut rng);
let (pub_b, priv_b) = X25519::generate(&mut rng);
let shared_a = priv_a.agree(&pub_b).expect("non-low-order");
let shared_b = priv_b.agree(&pub_a).expect("non-low-order");
assert_eq!(shared_a, shared_b);
```

Validation: RFC 7748 §5.2 KAT vectors are wired in `cargo test`, including
the iterated vectors at 1, 1000, and 1 000 000 iterations. The 1 M-iteration
tests are gated `#[ignore]`; run them with
`cargo test --release -- --ignored rfc7748_section5_2_iter_1m`.

#### Edwards Diffie-Hellman

Generation and agreement:

- `EdwardsDh::generate(curve, rng)`
- `EdwardsDhPrivateKey::agree_compressed_point(&peer) -> Option<Vec<u8>>`

Public-key compact form:

- `EdwardsDhPublicKey::to_wire_bytes()`
- `EdwardsDhPublicKey::from_wire_bytes(curve, bytes)`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::public_key::ec_edwards::ed25519;
use cryptography::vt::EdwardsDh;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[10u8; 48]);
let (pub_a, priv_a) = EdwardsDh::generate(ed25519(), &mut rng);
let (pub_b, priv_b) = EdwardsDh::generate(ed25519(), &mut rng);

let shared_a = priv_a.agree_compressed_point(&pub_b).expect("a");
let shared_b = priv_b.agree_compressed_point(&pub_a).expect("b");
assert_eq!(shared_a, shared_b);
```

#### Edwards ElGamal

Generation:

- `EdwardsElGamal::generate(curve, rng)`

Operations:

- `encrypt_point(...) -> Option<EcElGamalCiphertext>` (`None` for a
  plaintext outside the subgroup of order `n`)
- `encrypt_point_with_nonce(...) -> Option<EcElGamalCiphertext>` (also `None`
  for a nonce outside `[1, n)`)
- `encrypt_int(...)`
- `decrypt_point(...)`
- `decrypt_int(ciphertext, bound)`
- `add_ciphertexts(...)`

Public-key compact form:

- `EdwardsElGamalPublicKey::to_wire_bytes()`
- `EdwardsElGamalPublicKey::from_wire_bytes(curve, bytes)`

`decrypt_int(ciphertext, bound)` follows the EC-ElGamal convention: `bound` is
exclusive, so the result is `Some(m)` only for `m < bound`.

## Choosing an Algorithm Family

Use this decision rule:

- choose `CtrDrbgAes256` for practical random bytes inside this crate
- choose SHA-2 or SHA-3 for hashing; choose `Hmac<H>` for keyed integrity
- choose `Gcm<Aes256>` when you want authenticated symmetric encryption from
  the symmetric layer
- choose `RsaOaep` and `RsaPss` when you need standard RSA encryption or
  signatures with interoperable key formats
- choose `Dsa` or `Ecdsa` when you specifically need those signature families
- choose `Ecies` for short-Weierstrass hybrid public-key encryption
- choose `Ed25519` when you want the standard fixed Edwards signature system
- choose `Ecdh` or `EdwardsDh` for key agreement, then run the returned shared
  material through your own KDF
- choose `EcElGamal`, `EdwardsElGamal`, or `Paillier` when you explicitly need
  homomorphic behavior

## Low-Level Arithmetic Surfaces

The crate also exposes arithmetic building blocks through `cryptography::vt`:

- `BigUint`, `BigInt`, `MontgomeryCtx`
- `CurveParams`, `AffinePoint`
- `TwistedEdwardsCurve`, `EdwardsPoint`

The multiprecision layer itself — those bigint types plus the number
theory, GF(2^m) fields, and sampling — lives in the sibling
[rump](https://github.com/darrelllong/rump) crate, whose own
[MANUAL](https://github.com/darrelllong/rump/blob/main/MANUAL.md) documents
every one of its public APIs with worked, test-pinned examples. This crate
re-exports the bigint types through `cryptography::vt` only; everything else
in rump is reached as `rump::...` directly. `public_key::primes` keeps the
cryptographic policy that rump does not own (the hash-hardened primality test
for untrusted candidates, discrete-log group construction, and the CSPRNG
bridge).

Those are the right tools when you are testing formulas, reconstructing known
vectors, or experimenting with the math directly. They are not the normal
application-level entry points.

## Surface API Reference

This section is the API inventory. It focuses on externally callable surface
methods rather than implementation internals.

### CSPRNG Surface

#### `CtrDrbgAes256`

- constructors:
  - `new(&[u8; 48])`
  - `new_wiping(&mut [u8; 48])`
  - `instantiate(&[u8; 48], personalization_string)`
- reseeding:
  - `reseed(&[u8; 48])`
  - `reseed_wiping(&mut [u8; 48])`
  - `reseed_with_additional_input(&[u8; 48], additional_input)`
- output:
  - `generate(&mut [u8], Option<&[u8; 48]>)`
  - `fill_bytes(&mut [u8])` via `Csprng`
  - `next_u64()` via `Csprng`
- state inspection:
  - `reseed_counter()`

### Hash and XOF Surface

#### Fixed-output hashes

Applies to:

- `Md5`
- `Ripemd160`
- `Sha1`
- `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`
- `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`

Methods:

- `new()`
- `update(&[u8])`
- `finalize()` and `finalize_into(&mut [u8])`
- `finalize_reset()`: the digest, after which the hasher is scrubbed and
  reset to a fresh instance
- `digest(&[u8])`
- `zeroize()`

#### XOFs

Applies to:

- `Shake128`
- `Shake256`

Methods:

- `new()`
- `update(&[u8])`
- `digest(&[u8], &mut [u8])` as a one-shot helper on the concrete type
- `squeeze(&mut [u8])` via the `Xof` trait

#### `Hmac<H>`

- `new(key)`
- `update(data)`
- `finalize()`
- `compute(key, data)`
- `verify(key, data, tag)`

### Symmetric Surface

#### Block-cipher types

Fast and `Ct` block-cipher types share the same shape. The concrete exports are:

- AES: `Aes128`, `Aes192`, `Aes256`, `Aes128Ct`, `Aes192Ct`, `Aes256Ct`
- Camellia: `Camellia128`, `Camellia192`, `Camellia256`, `Camellia128Ct`,
  `Camellia192Ct`, `Camellia256Ct`
- CAST: `Cast128`, `Cast128Ct`, `Cast5`, `Cast5Ct`
- DES family: `Des`, `DesCt`, `TripleDes`, `TripleDesCt`
- Grasshopper: `Grasshopper`, `GrasshopperCt`
- Magma: `Magma`, `MagmaCt`
- PRESENT: `Present80`, `Present128`, `Present80Ct`, `Present128Ct`
- SEED: `Seed`, `SeedCt`
- Serpent: `Serpent128`, `Serpent192`, `Serpent256` (`Serpent128Ct`,
  `Serpent192Ct`, `Serpent256Ct` are aliases of them)
- SIMON parameter sets
- SPECK parameter sets
- SM4: `Sm4`, `Sm4Ct`
- Twofish: `Twofish128`, `Twofish192`, `Twofish256`, `Twofish128Ct`,
  `Twofish192Ct`, `Twofish256Ct`

Common methods:

- `new(&[u8; N])`
- `new_wiping(&mut [u8; N])` where implemented
- `encrypt_block(&[u8; BLOCK]) -> [u8; BLOCK]`
- `decrypt_block(&[u8; BLOCK]) -> [u8; BLOCK]`
- `encrypt(&mut [u8])` / `decrypt(&mut [u8])` through the `BlockCipher` trait

Special DES-family constructors:

- `des::key_schedule(u64)`, the expanded 16-round schedule; it lives in the `des`
  module and is not re-exported at the crate root
- `TripleDes::new_3key(&[u8; 24])` — rejects weak DES keys and any two equal
  key components (`DesKeyError::RepeatedKeyComponent`), as SP 800-67 requires
  three distinct keys
- `TripleDes::new_2key(&[u8; 16])` — `K1 = K3`, rejects `K1 = K2`
- `TripleDes::new_single_key(&[u8; 8])` — degenerates to single DES, for
  backward compatibility only
- `mode()` reports the keying option as a `TDesMode`
- wiping variants of the constructors
- `TripleDesCt` has the same constructors and methods over the constant-time
  DES core

#### Stream-cipher types

##### `ChaCha20`

- `new(&[u8; 32], &[u8; 12])`
- `with_counter(&[u8; 32], &[u8; 12], u32)`
- `new_wiping(&mut [u8; 32], &mut [u8; 12])`
- `apply_keystream(&mut [u8])`
- `fill(&mut [u8])`
- `keystream_block()`
- `set_counter(u32)`

##### `XChaCha20`

- `new(&[u8; 32], &[u8; 24])`
- `with_counter(&[u8; 32], &[u8; 24], u32)`
- `new_wiping(&mut [u8; 32], &mut [u8; 24])`
- `apply_keystream(&mut [u8])`
- `fill(&mut [u8])`
- `keystream_block()`
- `set_counter(u32)`

##### `Salsa20`

- `new(&[u8; 32], &[u8; 8])`
- `with_key_bytes(&[u8], &[u8; 8])`
- `with_counter(&[u8], &[u8; 8], u64)`
- wiping variants of those constructors
- `apply_keystream(&mut [u8])`
- `fill(&mut [u8])`
- `keystream_block()`
- `set_counter(u64)`

##### `Rabbit`

- `new(&[u8; 16], &[u8; 8])`
- `without_iv(&[u8; 16])`
- wiping variants
- `apply_keystream(&mut [u8])`
- `fill(&mut [u8])`
- `keystream_block()`

##### `Snow3g`, `Snow3gCt`, `Zuc128`, `Zuc128Ct`

- `new(&[u8; 16], &[u8; 16])`
- `new_wiping(&mut [u8; 16], &mut [u8; 16])`
- `next_word()`
- `fill(&mut [u8])`

#### Mode and MAC types

##### `Ecb<C>`

- `new(cipher)`
- `cipher()`
- `encrypt_nopad(&mut [u8])`
- `decrypt_nopad(&mut [u8])`

##### `Cbc<C>` and `Cfb<C>`

- `new(cipher)`
- `cipher()`
- `encrypt_nopad(iv, &mut [u8])`
- `decrypt_nopad(iv, &mut [u8])`

##### `Ofb<C>` and `Ctr<C>`

- `new(cipher)`
- `cipher()`
- `apply_keystream(iv_or_counter, &mut [u8])`

##### `Xts<C>`

- `new(data_cipher, tweak_cipher)`
- `data_cipher()`
- `tweak_cipher()`
- `encrypt_sector(&[u8; 16], &mut [u8])`
- `decrypt_sector(&[u8; 16], &mut [u8])`

Data units are 16 bytes to `XTS_MAX_DATA_UNIT_BLOCKS` (2^20) blocks
(SP 800-38E §4); both methods panic outside that range.

##### `Gcm<C>` and `GcmVt<C>`

- `new(cipher)`
- `cipher()`
- `compute_tag(nonce, aad, ciphertext)`
- `encrypt(nonce, aad, &mut [u8])`
- `decrypt(nonce, aad, &mut [u8], tag)`: takes only a full 16-byte tag, and
  returns `false` for over-long `data`, `aad` or `nonce` instead of panicking

`GcmVt<C>`'s GHASH is variable-time in both operands; use `Gcm<C>` wherever an
adversary can time decryption.

##### `Gmac<C>` and `GmacVt<C>`

- `new(cipher)`
- `cipher()`
- `compute(nonce, aad)`
- `verify(nonce, aad, tag)`

##### `Cmac<C>`

- `new(cipher)`
- `cipher()`
- `compute(data)`
- `verify(data, tag)`

### Public-Key Surface

#### Integer and finite-field types

##### `RsaPublicKey`

- arithmetic:
  - `exponent()`
  - `modulus()`
  - `encrypt_raw(&BigUint)`
- standard serialization:
  - `to_pkcs1_der()`, `from_pkcs1_der(...)`
  - `to_spki_der()`, `from_spki_der(...)`
  - `to_pkcs1_pem()`, `from_pkcs1_pem(...)`
  - `to_spki_pem()`, `from_spki_pem(...)`
- convenience serialization:
  - `to_xml()`, `from_xml(...)`

##### `RsaPrivateKey`

- arithmetic:
  - `exponent()`
  - `modulus()`
  - `decrypt_raw(&BigUint)`
- standard serialization:
  - `to_pkcs1_der()`, `from_pkcs1_der(...)`
  - `to_pkcs8_der()`, `from_pkcs8_der(...)`
  - `to_pkcs1_pem()`, `from_pkcs1_pem(...)`
  - `to_pkcs8_pem()`, `from_pkcs8_pem(...)`
- convenience serialization:
  - `to_xml()`, `from_xml(...)`

##### `Rsa`

- `from_primes_with_exponent(...)`
- `from_primes(...)`
- `generate_with_exponent(rng, bits, e)`
- `generate(rng, bits)`

##### `RsaOaep<H>`

- `encrypt(public, label, message)`
- `encrypt_rng(public, label, message, rng)`
- `decrypt(private, label, ciphertext)`
- `decrypt_rng(private, label, ciphertext, rng)`

##### `RsaPss<H>`

- `sign(private, message, salt)`
- `sign_rng(private, message, salt_len, rng)`
- `verify(public, message, signature, salt_len)`

##### `FfcParameterSize`, `FfcHash`, `FfcSeed` (`cryptography::public_key::primes`)

- `FfcParameterSize`: the FIPS 186-4 §4.2 pairs `L1024N160`, `L2048N224`,
  `L2048N256`, `L3072N256`; `l()`, `n()`, `from_lengths(l, n)`, `ALL`
- `FfcHash`: `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`,
  `Sha512_256`; `output_bits()`
- `FfcSeed::new(hash, domain_parameter_seed, counter, index)`; `hash()`,
  `domain_parameter_seed()`, `seedlen()`, `counter()`, `index()`

##### `DhParams`

- `new(p, q, g) -> Option<DhParams>` (hardened domain validation; the fields
  are private, so every `DhParams` is a validated group)
- `with_seed(p, q, g, seed) -> Option<DhParams>` (FIPS 186-4 A.1.1.3 and A.2.4)
- `modulus()`
- `subgroup_order()`
- `generator()`
- `seed() -> Option<&FfcSeed>`
- `to_key_blob()`, `from_key_blob(...)` (`[p, q, g]`, or eight fields with
  the seed record)
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_der()`, `from_der(...)` (RFC 3279 §2.3.3 X9.42 `DomainParameters`)

##### `DhPublicKey`

- `from_public_component(&DhParams, y)` (full public-key validation, `Option`)
- `modulus()`
- `subgroup_order()`
- `generator()`
- `public_component()`
- `params() -> Option<DhParams>` (re-validates the peer's group under the
  hardened test before it can be used to generate keys)
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_spki_der()`, `from_spki_der(...)`, `to_spki_pem()`, `from_spki_pem(...)` (RFC 3279 §2.3.3)

##### `DhPrivateKey`

- `modulus()`
- `subgroup_order()`
- `generator()`
- `exponent()`
- `to_public_key()`
- `params()`
- `agree_element(&DhPublicKey)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_pkcs8_der()`, `from_pkcs8_der(...)`, `to_pkcs8_pem()`, `from_pkcs8_pem(...)` (no standard defines it; OpenSSL's convention)

##### `Dh`

- `from_secret_exponent(p, q, g, x)` and `with_secret_exponent(&DhParams, x)`
  (`Option`; the group and `1 ≤ x < q` are validated)
- `generate_params(rng, size, hash)` (FB and FC only)
- `generate_toy_params(rng, bits)`
- `generate(&DhParams, rng)`

##### `DsaParams`

- `new(p, q, g) -> Option<DsaParams>`
- `with_seed(p, q, g, seed) -> Option<DsaParams>` (FIPS 186-4 A.1.1.3 and A.2.4)
- `modulus()`
- `subgroup_order()`
- `generator()`
- `seed() -> Option<&FfcSeed>`
- `to_key_blob()`, `from_key_blob(...)` (`[p, q, g]`, or eight fields with
  the seed record)
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_der()`, `from_der(...)` (RFC 3279 §2.3.2 `Dss-Parms`)

##### `DsaPublicKey`

- `from_public_component(&DsaParams, y)` (full public-key validation, `Option`)
- domain access:
  - `modulus()`
  - `subgroup_order()`
  - `generator()`
  - `public_component()`
  - `params() -> Option<DsaParams>` (hardened re-validation)
- verification:
  - `verify_message::<H>(...)`
  - `verify_message_bytes::<H>(...)`
  - `verify_digest_scalar(...)`
  - `verify(digest, signature)`
  - `verify_bytes(digest, signature_bytes)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`
  - `to_spki_der()`, `from_spki_der(...)`, `to_spki_pem()`, `from_spki_pem(...)` (RFC 3279 §2.3.2)

##### `DsaPrivateKey`

- domain/key access:
  - `modulus()`
  - `subgroup_order()`
  - `generator()`
  - `exponent()`
  - `to_public_key()`
  - `params()`
- signing:
  - `sign_digest_with_nonce(...)`
  - `sign_digest::<H>(...)`
  - `sign_digest_with_rng(...)`
  - `sign_message::<H>(...)`
  - `sign_message_with_rng::<H, R>(...)`
  - `sign_digest_bytes::<H>(...)`
  - `sign_digest_bytes_with_rng::<H, R>(...)`
  - `sign_message_bytes::<H>(...)`
  - `sign_message_bytes_with_rng::<H, R>(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`
  - `to_pkcs8_der()`, `from_pkcs8_der(...)`, `to_pkcs8_pem()`, `from_pkcs8_pem(...)` (RFC 5958 §2)

##### `DsaSignature`

- `r()`
- `s()`
- `to_der()`, `from_der(...)` (X9.62 / RFC 3279 `Dss-Sig-Value`)
- `to_key_blob()`, `from_key_blob(...)` (byte-identical to the DER form)

##### `Dsa`

- `from_secret_exponent(p, q, g, x)` and `with_secret_exponent(&DsaParams, x)`
  (`Option`; the group and `1 ≤ x < q` are validated)
- `generate_params(rng, size, hash)`
- `generate_toy_params(rng, bits)`
- `generate(&DsaParams, rng)`

##### `ElGamalPublicKey`

- parameter access:
  - `modulus()`
  - `generator()`
  - `ephemeral_exclusive_bound()`
  - `public_component()`
- encryption:
  - `encrypt_with_nonce(...)`
  - `encrypt(message, rng)`
  - `encrypt_bytes(message, rng)`
  (all `Option`; `None` for a message that is `0` or not below `p`)
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `ElGamalPrivateKey`

- key access:
  - `modulus()`
  - `exponent()`
  - `exponent_modulus()`
- decryption (`Option`; `None` for `γ` or `δ` outside `[1, p)`, or for a `γ`
  outside the order-`q` subgroup when the key carries `q`):
  - `decrypt_raw(...)`
  - `decrypt(...)`
  - `decrypt_bytes(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `ElGamalCiphertext`

- `gamma()`
- `delta()`
- `to_key_blob()`, `from_key_blob(...)`

##### `ElGamal`

- `from_secret_exponent(...)`
- `generate(rng, size, hash)` (group by FIPS 186-4 A.1.1.2 and A.2.3)
- `generate_toy(rng, bits)`

##### `PaillierPublicKey`

- parameter access:
  - `modulus()`
  - `generator()`
  - `max_plaintext_exclusive()`
- encryption and homomorphism:
  - `encrypt_with_nonce(...)`
  - `encrypt(message, rng)`
  - `encrypt_bytes(message, rng)`
  - `rerandomize(ciphertext, rng)`
  - `add_ciphertexts(lhs, rhs)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `PaillierPrivateKey`

- parameter access:
  - `modulus()`
  - `lambda()`
  - `decryption_factor()`
- decryption (`decrypt_raw` and `decrypt` return `Option`, `None` for a
  ciphertext `c ≥ n²`; `decrypt_bytes` propagates it):
  - `decrypt_raw(...)`
  - `decrypt(...)`
  - `decrypt_bytes(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `Paillier`

- `from_primes_with_base(...)`
- `from_primes(...)`
- `generate(rng, bits)`

##### `Rabin`, `SchmidtSamoa`, `Cocks`

These educational integer-scheme families all expose the same broad pattern:

- public side:
  - numeric accessors such as `modulus()` or `max_plaintext_exclusive()`
  - `encrypt_raw(...)`
  - `encrypt(...)`
  - `encrypt_bytes(...)`
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`
- private side:
  - scheme-specific key accessors
  - `decrypt_raw(...)`
  - `decrypt(...)`
  - `decrypt_bytes(...)`
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`
- namespace:
  - `from_primes(...)`
  - `generate(rng, bits)` (Rabin requires `bits ≥ Rabin::MIN_GENERATED_BITS`,
    140, so that one octet fits beside its 128-bit redundancy tag)

All three are deterministic maps with no padding layer (equal messages give
equal ciphertexts), documented as such on each type.

#### Short-Weierstrass EC types

##### `CurveParams`

- constructors:
  - `new(...)`
  - `new_binary(...)`
- curve arithmetic:
  - `gf2m_degree()`
  - `base_point()`
  - `is_on_curve(...)`
  - `negate(...)`
  - `add(...)`
  - `double(...)`
  - `scalar_mul(...)`
  - `diffie_hellman(...)`
  - `random_scalar(rng)`
  - `generate_keypair(rng)`
  - `scalar_invert(...)`
- point encoding:
  - `encode_point(...)`
  - `encode_point_compressed(...)`
  - `decode_point(...)`

##### `AffinePoint`

- `infinity()`
- `new(x, y)`
- `is_infinity()`

##### `EcdhPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_spki_der()`, `from_spki_der(...)`, `to_spki_pem()`, `from_spki_pem(...)` (RFC 5480; `to_*` return `Option`)

##### `EcdhPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- `agree_x_coordinate(&EcdhPublicKey)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_pkcs8_der()`, `from_pkcs8_der(...)`, `to_pkcs8_pem()`, `from_pkcs8_pem(...)` (RFC 5958 / RFC 5915)
- `to_sec1_der()`, `from_sec1_der(...)`, `to_sec1_pem()`, `from_sec1_pem(...)` (RFC 5915)

##### `Ecdh`

- `generate(curve, rng)`
- `from_secret_scalar(curve, secret)`

##### `EcdsaPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- verification:
  - `verify_message::<H>(...)`
  - `verify_message_bytes::<H>(...)`
  - `verify(digest, signature)`
  - `verify_digest_scalar(...)`
  - `verify_bytes(digest, signature_bytes)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`
  - `to_spki_der()`, `from_spki_der(...)`, `to_spki_pem()`, `from_spki_pem(...)` (RFC 5480; `to_*` return `Option`)

##### `EcdsaPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- signing:
  - `sign_digest_with_nonce(...)`
  - `sign_digest::<H>(...)`
  - `sign_digest_with_rng(...)`
  - `sign_message::<H>(...)`
  - `sign_message_with_rng::<H, R>(...)`
  - `sign_digest_bytes::<H>(...)`
  - `sign_digest_bytes_with_rng::<H, R>(...)`
  - `sign_message_bytes::<H>(...)`
  - `sign_message_bytes_with_rng::<H, R>(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`
  - `to_pkcs8_der()`, `from_pkcs8_der(...)`, `to_pkcs8_pem()`, `from_pkcs8_pem(...)` (RFC 5958 / RFC 5915)
  - `to_sec1_der()`, `from_sec1_der(...)`, `to_sec1_pem()`, `from_sec1_pem(...)` (RFC 5915)

##### `EcdsaSignature`

- `r()`
- `s()`
- `to_low_s(curve)`
- `to_der()`, `from_der(...)` (X9.62 / RFC 3279 §2.2.3 `ECDSA-Sig-Value`)
- `to_key_blob()`, `from_key_blob(...)` (byte-identical to the DER form)

##### `Ecdsa`

- `generate(curve, rng)`
- `from_secret_scalar(curve, secret)`

##### `EciesPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- `encrypt(setup, message, shared_info1, shared_info2, rng)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_spki_der()`, `from_spki_der(...)`, `to_spki_pem()`, `from_spki_pem(...)` (RFC 5480; `to_*` return `Option`)

##### `EciesPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- `decrypt(setup, ciphertext, shared_info1, shared_info2)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- `to_pkcs8_der()`, `from_pkcs8_der(...)`, `to_pkcs8_pem()`, `from_pkcs8_pem(...)` (RFC 5958 / RFC 5915)
- `to_sec1_der()`, `from_sec1_der(...)`, `to_sec1_pem()`, `from_sec1_pem(...)` (RFC 5915)

##### `Ecies`

- `generate(curve, rng)`

##### `EciesSetup`

- `RECOMMENDED`
- `new(kdf, encryption, mac, dh_primitive, point_format)`
- `kdf()`, `encryption()`, `mac()`, `dh_primitive()`, `point_format()`

##### `EciesMac`

- `tag_len()`

##### `EcElGamalPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- encryption:
  - `encrypt_point(...) -> Option<EcElGamalCiphertext>`
  - `encrypt_point_with_nonce(...) -> Option<EcElGamalCiphertext>`
  - `encrypt(...)`
  - `encrypt_int(...)`
  - `add_ciphertexts(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `EcElGamalPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- decryption:
  - `decrypt_point(...)`
  - `decrypt(...)`
  - `decrypt_int(ciphertext, bound)`, exclusive `bound`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `EcElGamalCiphertext`

- `c1()`
- `c2()`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
  (the blob, PEM and XML carry `c1form, c1x, c1y, c2form, c2x, c2y`; form `0`
  is the point at infinity, `4` a finite point)

##### `EcElGamal`

- `generate(curve, rng)`

#### Edwards-curve types

##### `TwistedEdwardsCurve`

- constructors and curve identity:
  - `new(...)` (parameters the caller vouches for)
  - `from_explicit(...)` (parameters from outside the process; Ed25519 by
    comparison, otherwise validated with `p` capped at
    `MAX_EXPLICIT_FIELD_BITS` and the cofactor at `MAX_EXPLICIT_COFACTOR`)
  - `same_curve(...)`
  - `is_canonical_point(...)`
- curve arithmetic:
  - `base_point()`
  - `is_on_curve(...)`
  - `negate(...)`
  - `add(...)`
  - `double(...)`
  - `scalar_mul(...)`
  - `scalar_mul_base(...)`
  - `diffie_hellman(...)`
  - `random_scalar(rng)`
  - `generate_keypair(rng)`
  - `scalar_invert(...)`
- point encoding:
  - `encode_point(...)`
  - `decode_point(...)`

##### `EdwardsPoint`

- `neutral()`
- `new(x, y)`
- `is_neutral()`

##### `Ed25519PublicKey`

- `public_point()`
- `to_key_blob()`, `from_key_blob(...)`
- `to_raw_bytes()`, `from_raw_bytes(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- verification:
  - `verify_message(...)`
  - `verify_message_bytes(...)`

##### `Ed25519PrivateKey`

- `seed()`
- `scalar()`
- `to_public_key()`
- `to_key_blob()`, `from_key_blob(...)`
- `to_raw_bytes()`, `from_raw_bytes(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`
- signing:
  - `sign_message(...)`
  - `sign_message_bytes(...)`

##### `Ed25519Signature`

- `nonce_point()`
- `response()`
- `to_key_blob()`, `from_key_blob(...)`

##### `Ed25519`

- `generate(rng)`
- `from_seed([u8; 32])`

##### `EdDsaPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- verification:
  - `verify_message::<H>(...)`
  - `verify_message_bytes::<H>(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `EdDsaPrivateKey`

- `curve()`
- `private_scalar()`
- `public_point()`
- `to_public_key()`
- signing:
  - `sign_message_with_nonce::<H>(...)`
  - `sign_message::<H, R>(...)`
  - `sign_message_bytes::<H, R>(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `EdDsaSignature`

- `nonce_point()`
- `response()`
- `to_key_blob()`
- `from_key_blob(blob, curve)`

##### `EdDsa`

- `generate(curve, rng)`
- `from_secret_scalar(curve, secret)`

##### `EdwardsDhPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

##### `EdwardsDhPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- `agree_compressed_point(&EdwardsDhPublicKey)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

##### `EdwardsDh`

- `generate(curve, rng)`

##### `EdwardsElGamalPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- encryption:
  - `encrypt_point(...) -> Option<EcElGamalCiphertext>`
  - `encrypt_point_with_nonce(...) -> Option<EcElGamalCiphertext>`
  - `encrypt_int(...)`
  - `add_ciphertexts(...)`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `EdwardsElGamalPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- decryption:
  - `decrypt_point(...)`
  - `decrypt_int(ciphertext, bound)`, exclusive `bound`
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `EdwardsElGamalCiphertext`

- `c1()`
- `c2()`
- `to_key_blob()`
- `from_key_blob(curve, blob)`
- `to_pem()`
- `from_pem(curve, pem)`
- `to_xml()`
- `from_xml(curve, xml)`

##### `EdwardsElGamal`

- `generate(curve, rng)`

#### Post-quantum lattice types

##### `MlKemParameterSet`

- `MlKem512`, `MlKem768`, `MlKem1024`
- `k()`
- `public_key_len()`
- `private_key_len()`
- `ciphertext_len()`
- `shared_secret_len()`

##### `MlKemPublicKey`

- metadata:
  - `parameter_set()`
- encoding:
  - `to_wire_bytes()`, `from_wire_bytes(params, ...)`
  - `to_key_blob()`, `from_key_blob(...)`

##### `MlKemPrivateKey`

- metadata:
  - `parameter_set()`
- encoding:
  - `to_wire_bytes()`, `from_wire_bytes(params, ...)`
  - `to_key_blob()`, `from_key_blob(...)`

##### `MlKemCiphertext`

- metadata:
  - `parameter_set()`
- encoding:
  - `to_wire_bytes()`, `from_wire_bytes(params, ...)`

##### `MlKemSharedSecret`

- `to_wire_bytes()`
- `from_wire_bytes(...)`

##### `MlKem`

- `keygen(params, rng)`
- `keygen_from_seed(params, d, z)`
- `encaps(public_key, rng)`
- `encaps_with_randomness(public_key, m)`
- `decaps(private_key, ciphertext)`

##### `MlDsaParameterSet`

- `MlDsa44`, `MlDsa65`, `MlDsa87`
- `public_key_len()`
- `private_key_len()`
- `signature_len()`

##### `MlDsaPublicKey`

- metadata:
  - `parameter_set()`
- encoding:
  - `to_wire_bytes()`, `from_wire_bytes(params, ...)`
  - `to_key_blob()`, `from_key_blob(...)`

##### `MlDsaPrivateKey`

- metadata:
  - `parameter_set()`
- encoding:
  - `to_wire_bytes()`, `from_wire_bytes(params, ...)`
  - `to_key_blob()`, `from_key_blob(...)`

##### `MlDsaSignature`

- metadata:
  - `parameter_set()`
- encoding:
  - `to_wire_bytes()`, `from_wire_bytes(params, ...)`

##### `MlDsa`

- `keygen(params, rng)`
- `keygen_from_seed(params, seed)`
- `sign(private_key, message, rng)`
- `sign_deterministic(...)` — FIPS 204 deterministic signing (`rnd` is 32 zero bytes)
- `sign_with_randomness(private_key, message, rnd)` — hedged signing with caller-supplied `rnd`
- `sign_with_randomness_and_context(private_key, message, rnd, ctx)`
- `verify(public_key, message, signature)`
- `verify_with_context(public_key, message, signature, ctx) -> Option<bool>`
  (`None` when `ctx` exceeds 255 bytes, FIPS 204 Algorithm 3's error
  indication; `Some(false)` for an invalid signature or a parameter-set
  mismatch)

#### RFC 7748 constant-time ECDH types

##### `X25519`

- `scalar_mult(&[u8; 32], &[u8; 32]) -> [u8; 32]`
- `scalar_mult_base(&[u8; 32]) -> [u8; 32]`
- `generate(rng) -> (X25519PublicKey, X25519PrivateKey)`

##### `X25519PrivateKey`

- `from_raw_bytes(&[u8; 32])`
- `from_raw_bytes_wiping(&mut [u8; 32])`
- `to_raw_bytes()`
- `to_public_key()`
- `agree(&X25519PublicKey) -> Option<[u8; 32]>`

##### `X25519PublicKey`

- `from_raw_bytes(&[u8; 32])`
- `to_raw_bytes()`

##### `X448`

- `scalar_mult(&[u8; 56], &[u8; 56]) -> [u8; 56]`
- `scalar_mult_base(&[u8; 56]) -> [u8; 56]`
- `generate(rng) -> (X448PublicKey, X448PrivateKey)`

##### `X448PrivateKey`

- `from_raw_bytes(&[u8; 56])`
- `from_raw_bytes_wiping(&mut [u8; 56])`
- `to_raw_bytes()`
- `to_public_key()`
- `agree(&X448PublicKey) -> Option<[u8; 56]>`

##### `X448PublicKey`

- `from_raw_bytes(&[u8; 56])`
- `to_raw_bytes()`
