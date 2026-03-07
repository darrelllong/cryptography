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
    ElGamal, Paillier, Rsa, RsaOaep, RsaPss,
};
```

## Entropy Requirements

This crate does **not** provide an operating-system entropy source.

That is deliberate. If you use `CtrDrbgAes256`, key-generation APIs, randomized
padding, or any other randomness-dependent operation, you must supply the seed
material yourself from a high-entropy external source.

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

## API Conventions

The public surface follows these naming rules:

- `to_wire_bytes` / `from_wire_bytes` are compact standard encodings that do
  not carry full algorithm parameters
- `to_key_blob` / `from_key_blob` are the crate-defined self-describing binary
  encodings
- `to_raw_bytes` / `from_raw_bytes` are used where the standard representation
  is already a fixed-width raw byte string, notably `Ed25519`
- explicit caller-supplied randomness uses `*_with_nonce`
- Diffie-Hellman style APIs name the returned form explicitly:
  `agree_element`, `agree_x_coordinate`, `agree_compressed_point`

## CSPRNG

### Root-level practical DRBG

The practical generator is `CtrDrbgAes256`, exported at the crate root. It is a
DRBG, not an entropy source.

Key methods:

- `CtrDrbgAes256::new(&[u8; 48])`
- `CtrDrbgAes256::new_wiping(&mut [u8; 48])`
- `reseed(&[u8; 48])`
- `reseed_wiping(&mut [u8; 48])`
- `generate(&mut [u8], Option<&[u8; 48]>)`
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

### Historical reference generators

The historical generators are available from the `cprng` module rather than
the crate root:

- `cryptography::cprng::blum_blum_shub::BlumBlumShub`
- `cryptography::cprng::blum_micali::BlumMicali`

They expose inherent byte-generation methods:

- `new(...)`
- `state()`
- `next_bit()`
- `fill_bytes(&mut [u8])`

They are for study and experimentation, not as the crate's practical default.

### Entropy checklist

Before using `CtrDrbgAes256` or any public-key `generate(...)` API, make sure:

- the seed came from a real external entropy source
- the seed is not reused across machines, users, or runs
- test/example literals never survive into deployment code
- any reseed path is held to the same entropy standard as the initial seed

## Hash, XOF, and MAC

### Fixed-output hashes

The crate exports:

- `Sha1`
- `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`
- `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`

All fixed-output hashes support:

- `new()`
- `update(&[u8])`
- `finalize()`
- `digest(&[u8])`

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
- DES: `Des`, `DesCt`, `TripleDes`
- Grasshopper: `Grasshopper`, `GrasshopperCt`
- Magma: `Magma`, `MagmaCt`
- PRESENT: `Present80`, `Present128`, and `Ct` variants
- SEED: `Seed`, `SeedCt`
- Serpent: `Serpent128`, `Serpent192`, `Serpent256`, plus `Ct` variants
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
- `Ofb<C>`
- `Ctr<C>`
- `Xts<C>`
- `Cmac<C>`
- `Gcm<C>`
- `GcmVt<C>`
- `Gmac<C>`
- `GmacVt<C>`

Constructor pattern:

- `Mode::new(cipher)`

Representative methods:

- `encrypt_nopad` / `decrypt_nopad` for `Ecb`, `Cbc`, `Cfb`
- `apply_keystream` for `Ofb`, `Ctr`
- `encrypt_sector` / `decrypt_sector` for `Xts`
- `encrypt`, `decrypt`, `compute_tag` for `Gcm` and `GcmVt`

`Gcm` and `Gmac` are the safe-default constant-time GHASH-backed variants.
`GcmVt` and `GmacVt` are the explicit variable-time reference/performance
variants.

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

### Worked example: `encrypt_file` / `decrypt_file` with counter mode

This is a minimal complete file-encryption example built directly from the
surface API.

Important caveat: `CTR` mode gives confidentiality only. It does **not**
authenticate the ciphertext. In real deployments, pair this with a MAC or use
`Gcm<Aes256>` instead unless a separate integrity layer already exists.

```rust
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
```

Round-trip usage:

```rust
use std::path::Path;

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

Root-level exports:

- `ChaCha20`
- `XChaCha20`
- `Salsa20`
- `Rabbit`
- `Snow3g`, `Snow3gCt`
- `Zuc128`, `Zuc128Ct`

Common method pattern:

- `new(key, nonce_or_iv)`
- `apply_keystream(&mut [u8])`
- `fill(&mut [u8])`

Some stream ciphers also expose:

- `with_counter(...)` and `set_counter(...)` for ChaCha20/XChaCha20
- `without_iv(...)` for Rabbit
- `keystream_block()` for ChaCha20, XChaCha20, Rabbit

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
use cryptography::Snow3g;

let mut snow = Snow3g::new(&[0u8; 16], &[0u8; 16]);
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

- `Rsa::generate(rng, bits)`
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
- `RsaPss::<H>::sign(private, message, salt)`
- `RsaPss::<H>::sign_rng(private, message, rng)`
- `RsaPss::<H>::verify(public, message, signature)`

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
let plaintext = RsaOaep::<Sha256>::decrypt(&private, b"label", &ciphertext)
    .expect("oaep decrypt");
assert_eq!(plaintext, b"hello");

let signature = RsaPss::<Sha512>::sign_rng(&private, b"hello", &mut rng)
    .expect("pss sign");
assert!(RsaPss::<Sha512>::verify(&public, b"hello", &signature));
```

#### Diffie-Hellman over finite fields

Key types:

- `DhParams`
- `DhPublicKey`
- `DhPrivateKey`

Generation:

- `Dh::generate_params(rng, bits)`
- `Dh::generate(&params, rng)`

Agreement:

- `DhPrivateKey::agree_element(&peer) -> Option<BigUint>`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::Dh;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[9u8; 48]);
let params = Dh::generate_params(&mut rng, 256).expect("params");
let (pub_a, priv_a) = Dh::generate(&params, &mut rng);
let (pub_b, priv_b) = Dh::generate(&params, &mut rng);

let shared_a = priv_a.agree_element(&pub_b).expect("agree a");
let shared_b = priv_b.agree_element(&pub_a).expect("agree b");
assert_eq!(shared_a, shared_b);
```

#### DSA

Generation:

- `Dsa::generate(rng, bits)`
- `Dsa::from_secret_exponent(...)`

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

Example:

```rust
use cryptography::{CtrDrbgAes256, Sha256};
use cryptography::vt::Dsa;

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[3u8; 48]);
let (public, private) = Dsa::generate(&mut rng, 1024).expect("dsa");

let sig = private.sign_message::<Sha256>(b"message").expect("sign");
assert!(public.verify_message::<Sha256>(b"message", &sig));
```

#### ElGamal, Paillier, and the educational schemes

Normal APIs:

- `ElGamalPublicKey::encrypt(...)`
- `ElGamalPublicKey::encrypt_with_nonce(...)`
- `ElGamalPrivateKey::decrypt(...)`
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
let sum = private.decrypt_raw(&sum_ct);
assert_eq!(sum, BigUint::from_u64(30));
```

### Short-Weierstrass EC

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

Generation and agreement:

- `Ecdh::generate(curve, rng)`
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

Wire encoding for public keys:

- `EcdsaPublicKey::to_wire_bytes()`
- `EcdsaPublicKey::from_wire_bytes(curve, bytes)`

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

Generation:

- `Ecies::generate(curve, rng)`

Hybrid encryption:

- `EciesPublicKey::encrypt(message, rng) -> Vec<u8>`
- `EciesPrivateKey::decrypt(ciphertext) -> Option<Vec<u8>>`

Public-key compact form:

- `EciesPublicKey::to_wire_bytes()`
- `EciesPublicKey::from_wire_bytes(curve, bytes)`

Example:

```rust
use cryptography::CtrDrbgAes256;
use cryptography::vt::{p256, Ecies};

// Fixed seed for a deterministic example only.
let mut rng = CtrDrbgAes256::new(&[4u8; 48]);
let (public, private) = Ecies::generate(p256(), &mut rng);

let ciphertext = public.encrypt(b"ecies payload", &mut rng);
let plaintext = private.decrypt(&ciphertext).expect("decrypt");
assert_eq!(plaintext, b"ecies payload");
```

#### EC-ElGamal

Generation:

- `EcElGamal::generate(curve, rng)`

Operations:

- `encrypt_point(...)`
- `encrypt_point_with_nonce(...)`
- `encrypt(...)`
- `encrypt_int(...)`
- `decrypt_point(...)`
- `decrypt(...)`
- `decrypt_int(...)`
- `add_ciphertexts(...)`

Public-key compact form:

- `EcElGamalPublicKey::to_wire_bytes()`
- `EcElGamalPublicKey::from_wire_bytes(curve, bytes)`

This is the additive-homomorphic EC ElGamal layer, not ECIES.

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

- `encrypt_point(...)`
- `encrypt_point_with_nonce(...)`
- `encrypt_int(...)`
- `decrypt_point(...)`
- `decrypt_int(...)`
- `add_ciphertexts(...)`

Public-key compact form:

- `EdwardsElGamalPublicKey::to_wire_bytes()`
- `EdwardsElGamalPublicKey::from_wire_bytes(curve, bytes)`

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
- reseeding:
  - `reseed(&[u8; 48])`
  - `reseed_wiping(&mut [u8; 48])`
- output:
  - `generate(&mut [u8], Option<&[u8; 48]>)`
  - `fill_bytes(&mut [u8])` via `Csprng`
  - `next_u64()` via `Csprng`
- state inspection:
  - `reseed_counter()`

#### `BlumBlumShub` and `BlumMicali`

- constructors:
  - `new(...)`
- inspection:
  - `state()`
- output:
  - `next_bit()`
  - `fill_bytes(&mut [u8])`

### Hash and XOF Surface

#### Fixed-output hashes

Applies to:

- `Sha1`
- `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256`
- `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`

Methods:

- `new()`
- `update(&[u8])`
- `finalize()`
- `digest(&[u8])`

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
- DES family: `Des`, `DesCt`, `TripleDes`
- Grasshopper: `Grasshopper`, `GrasshopperCt`
- Magma: `Magma`, `MagmaCt`
- PRESENT: `Present80`, `Present128`, `Present80Ct`, `Present128Ct`
- SEED: `Seed`, `SeedCt`
- Serpent: `Serpent128`, `Serpent192`, `Serpent256`, `Serpent128Ct`,
  `Serpent192Ct`, `Serpent256Ct`
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

- `key_schedule(u64)`
- `TripleDes::new_3key(&[u8; 24])`
- `TripleDes::new_2key(&[u8; 16])`
- `TripleDes::new_single_key(&[u8; 8])`
- wiping variants of the `TripleDes` constructors

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
- `new_wiping(...)` where implemented
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

##### `Gcm<C>` and `GcmVt<C>`

- `new(cipher)`
- `cipher()`
- `compute_tag(nonce, aad, ciphertext)`
- `encrypt(nonce, aad, &mut [u8])`
- `decrypt(nonce, aad, &mut [u8], tag)`

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

##### `RsaPss<H>`

- `sign(private, message, salt)`
- `sign_rng(private, message, rng)`
- `verify(public, message, signature)`

##### `DhParams`

- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

##### `DhPublicKey`

- `modulus()`
- `subgroup_order()`
- `generator()`
- `public_component()`
- `params()`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

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

##### `Dh`

- `generate_params(rng, bits)`
- `generate(&DhParams, rng)`

##### `DsaPublicKey`

- domain access:
  - `modulus()`
  - `subgroup_order()`
  - `generator()`
  - `public_component()`
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

##### `DsaPrivateKey`

- domain/key access:
  - `modulus()`
  - `subgroup_order()`
  - `generator()`
  - `exponent()`
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

##### `DsaSignature`

- `r()`
- `s()`
- `to_key_blob()`, `from_key_blob(...)`

##### `Dsa`

- `from_secret_exponent(...)`
- `generate(rng, bits)`

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
- serialization:
  - `to_key_blob()`, `from_key_blob(...)`
  - `to_pem()`, `from_pem(...)`
  - `to_xml()`, `from_xml(...)`

##### `ElGamalPrivateKey`

- key access:
  - `modulus()`
  - `exponent()`
  - `exponent_modulus()`
- decryption:
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
- `generate(rng, bits)`

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
- decryption:
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
  - `generate(rng, bits)`

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

##### `EcdhPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- `agree_x_coordinate(&EcdhPublicKey)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

##### `Ecdh`

- `generate(curve, rng)`

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

##### `EcdsaSignature`

- `r()`
- `s()`
- `to_key_blob()`, `from_key_blob(...)`

##### `Ecdsa`

- `generate(curve, rng)`
- `from_secret_scalar(curve, secret)`

##### `EciesPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- `encrypt(message, rng)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

##### `EciesPrivateKey`

- `curve()`
- `private_scalar()`
- `to_public_key()`
- `decrypt(ciphertext_bytes)`
- `to_key_blob()`, `from_key_blob(...)`
- `to_pem()`, `from_pem(...)`
- `to_xml()`, `from_xml(...)`

##### `Ecies`

- `generate(curve, rng)`

##### `EcElGamalPublicKey`

- `curve()`
- `public_point()`
- `to_wire_bytes()`, `from_wire_bytes(curve, ...)`
- encryption:
  - `encrypt_point(...)`
  - `encrypt_point_with_nonce(...)`
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
  - `decrypt_int(...)`
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

##### `EcElGamal`

- `generate(curve, rng)`

#### Edwards-curve types

##### `TwistedEdwardsCurve`

- constructors and curve identity:
  - `new(...)`
  - `same_curve(...)`
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
  - `encrypt_point(...)`
  - `encrypt_point_with_nonce(...)`
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
  - `decrypt_int(...)`
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
