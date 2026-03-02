# cryptography

Pure, safe, portable Rust implementations of classical and modern ciphers
written directly from the published specifications.

Project-wide implementation rules:

- pure idiomatic Rust
- no architecture intrinsics
- no C/FFI escape hatches
- as few dependencies as practical

That policy applies to the symmetric, hash, CSPRNG, and public-key layers
alike. The goal is to keep the code readable, portable, and auditable in one
language, and to add a dependency only when it clearly buys real
interoperability or maintenance value.

Implemented families:

- DES and Triple-DES
- AES (`Aes128/192/256`) plus software constant-time variants (`Aes*Ct`)
- CAST-128 / CAST5 plus `Cast128Ct`
- Camellia (`Camellia128/192/256`) plus software constant-time variants
- Serpent (`Serpent128/192/256`) plus software constant-time variants
- Twofish (`Twofish128/192/256`) plus software constant-time variants
- SEED plus `SeedCt`
- SIMON (all 10 published variants)
- SPECK (all 10 published variants)
- PRESENT (`Present80` / `Present128`) plus software constant-time variants
- Magma plus `MagmaCt`
- Grasshopper plus `GrasshopperCt`
- SM4 / SMS4 plus `Sm4Ct`
- ChaCha20 and XChaCha20
- Salsa20
- ZUC-128 plus `Zuc128Ct`

Supporting primitives:

- SHA-3 (`Sha3_224/256/384/512`)
- SHAKE (`Shake128`, `Shake256`)
- Generic block-cipher modes: `Ecb`, `Cbc`, `Cfb`, `Ofb`, `Ctr`, `Cmac`
- Historical CSPRNGs: `BlumBlumShub`, `BlumMicali`
- SP 800-90A Rev. 1: `CtrDrbgAes256`

Documentation is split by domain:

- [ANALYSIS.md](ANALYSIS.md): top-level overview, coverage, and experiment notes
- [SYMMETRIC.md](SYMMETRIC.md): symmetric ciphers, modes, hashes, and throughput
- [ASYMMETRIC.md](ASYMMETRIC.md): public-key primitives, wrappers, serialization, and latency

## HOWTO

### Keys, IVs, nonces, and counters

Most constructors encode the required key size in the type signature, so the
expected size is visible in the API:

- `Aes128`, `Sm4`, `Seed`, `Camellia128`, `Serpent128`, `Twofish128`, and many
  others take `&[u8; 16]`
- `Aes192`, `Camellia192`, `Serpent192`, `Twofish192` take `&[u8; 24]`
- `Aes256`, `Camellia256`, `Serpent256`, `Twofish256` take `&[u8; 32]`
- `Present80` takes `&[u8; 10]`; `Present128` takes `&[u8; 16]`
- `Des` uses an 8-byte DES key; `TripleDes::new_2key` uses 16 bytes; `TripleDes::new_3key` uses 24 bytes

The main variable-length exceptions are:

- `Cast128::with_key_bytes(&key)` for 5..=16-byte keys
- `Salsa20::with_key_bytes(&key, &nonce)` for 16- or 32-byte keys

Stream-cipher nonce/IV sizes are fixed by the constructor:

- `Salsa20`: 8-byte nonce
- `ChaCha20`: 12-byte nonce, optional 32-bit block counter via `with_counter`
- `XChaCha20`: 24-byte nonce, optional 32-bit block counter via `with_counter`
- `Zuc128`: 16-byte key and 16-byte IV

The mode wrappers follow the block size or the standard profile:

- `Cbc`, `Cfb`, `Ofb`, and block-cipher `Ctr` take an IV/counter block exactly
  one cipher block long
- `Gcm` uses a 12-byte nonce in the standard fast path shown here
- `Xts` takes a 16-byte tweak value and two independent 128-bit block-cipher
  keys (for example two separate `Aes128` instances)

### Generic block-cipher example

All block ciphers implement the shared `BlockCipher` trait for in-place
operation on a mutable byte slice:

```rust
use cryptography::{Aes128, BlockCipher};

let key = [0u8; 16]; // AES-128 = 16-byte key
let cipher = Aes128::new(&key);
let mut block = [0u8; 16];

cipher.encrypt(&mut block);
cipher.decrypt(&mut block);
```

### Fixed-size block example

Each block cipher type also exposes typed helpers when the block size is known
at compile time:

```rust
use cryptography::Sm4;

let key = [0u8; 16]; // SM4 = 16-byte key
let cipher = Sm4::new(&key);
let block = [0u8; 16];

let ct = cipher.encrypt_block(&block);
let pt = cipher.decrypt_block(&ct);
assert_eq!(pt, block);
```

### Constant-time example

If you need the software constant-time path, use the dedicated `Ct` type:

```rust
use cryptography::Aes128Ct;

let key = [0u8; 16];
let cipher = Aes128Ct::new(&key);
let block = [0u8; 16];

let ct = cipher.encrypt_block(&block);
let pt = cipher.decrypt_block(&ct);
assert_eq!(pt, block);
```

### Modes of operation example

The generic mode wrappers accept any `BlockCipher` in the crate:

```rust
use cryptography::{Aes128, Cbc, Cmac, Ctr, Gcm, Xts};

let key = [0u8; 16];
let cipher = Aes128::new(&key);

let mut cbc_buf = [0u8; 32];
let iv = [0u8; 16]; // one AES block
Cbc::new(cipher).encrypt_nopad(&iv, &mut cbc_buf);

let mut ctr_buf = [0u8; 37];
let counter = [0u8; 16]; // one AES block
Ctr::new(Aes128::new(&key)).apply_keystream(&counter, &mut ctr_buf);

let tag = Cmac::new(Aes128::new(&key)).compute(b"header and body");
assert_eq!(tag.len(), 16);

let mut gcm_buf = [0u8; 23];
let nonce = [0u8; 12]; // standard 96-bit GCM nonce
let aad = b"header";
let tag = Gcm::new(Aes128::new(&key)).encrypt(&nonce, aad, &mut gcm_buf);
assert!(Gcm::new(Aes128::new(&key)).decrypt(&nonce, aad, &mut gcm_buf, &tag));

let mut sector = [0u8; 32];
let tweak = [0u8; 16]; // one 16-byte tweak block
let data_key = [0u8; 16];
let tweak_key = [1u8; 16];
Xts::new(Aes128::new(&data_key), Aes128::new(&tweak_key)).encrypt_sector(&tweak, &mut sector);
```

The current mode layer implements:

- SP 800-38A: ECB, CBC, CFB (full-block), OFB, CTR
- SP 800-38B: CMAC
- SP 800-38D: GCM, GMAC
- SP 800-38E: XTS (for 128-bit block ciphers)

RFC 8452's AES-GCM-SIV was reviewed while designing this layer. It is a
nonce-misuse-resistant AEAD built around AES and `POLYVAL`, so it belongs in a
later authenticated-encryption layer rather than in the basic mode adapters
added here.

### Stream-cipher example

ZUC produces keystream words and can fill a caller-supplied buffer, while
Salsa20, ChaCha20, and XChaCha20 apply their keystream directly to plaintext
or ciphertext:

```rust
use cryptography::{ChaCha20, Salsa20, XChaCha20, Zuc128};

let mut msg = *b"example message...";
let mut salsa = Salsa20::new(&[0u8; 32], &[0u8; 8]); // 32-byte key, 8-byte nonce
let mut chacha = ChaCha20::with_counter(&[1u8; 32], &[0u8; 12], 7); // 32-byte key, 12-byte nonce, u32 counter
let mut xchacha = XChaCha20::with_counter(&[2u8; 32], &[0u8; 24], 7); // 32-byte key, 24-byte nonce, u32 counter
let mut buf = [0u8; 64];
let mut zuc = Zuc128::new(&[0u8; 16], &[0u8; 16]); // 16-byte key, 16-byte IV

salsa.apply_keystream(&mut msg);
chacha.apply_keystream(&mut msg);
xchacha.apply_keystream(&mut msg);
zuc.fill(&mut buf);
```

### Hash / XOF / HMAC example

SHA-1 / SHA-2 / SHA-3 expose fixed-output hashes, and SHAKE exposes
extendable-output functions:

For keyed integrity, do not treat raw SHA-1 / SHA-2 digests as MACs. Those
Merkle-Damgard hashes have the usual length-extension caveat; use `Hmac<H>`
instead, or prefer SHA-3 / SHAKE when sponge-based hashing is a better fit.

```rust
use cryptography::{Digest, Hmac, Sha256, Sha3_256, Shake128};

let digest = Sha256::digest(b"abc");
let mut out = [0u8; 32];
Shake128::digest(b"abc", &mut out);
let tag = Hmac::<Sha3_256>::compute(b"key", b"message");

assert_eq!(digest.len(), 32);
assert_eq!(out.len(), 32);
assert_eq!(tag.len(), Sha3_256::OUTPUT_LEN);
```

### CSPRNG example

The shared `Csprng` trait lets callers fill caller-owned buffers regardless of
which generator is underneath:

```rust
use cryptography::{Csprng, CtrDrbgAes256};

let seed_material = [0u8; 48]; // 32-byte AES key + 16-byte V
let mut drbg = CtrDrbgAes256::new(&seed_material);
let mut out = [0u8; 32];
drbg.fill_bytes(&mut out);
```

### Fast vs `Ct` variants

For AES, CAST-128, DES, Twofish, Magma, Grasshopper, SM4, and ZUC, the default
type is the fast software implementation and the `Ct` type is the separate
constant-time software path.

Use the fast path when:

- you want the fastest portable software implementation in this crate
- your threat model does not require side-channel-resistant software behavior

Use the `Ct` path when:

- you need a software-only constant-time implementation
- you are willing to pay the throughput penalty documented in `ANALYSIS.md`

The `Ct` types are distinct on purpose; the API makes the tradeoff explicit.

### Wiping caller-owned keys

Cipher types that retain expanded round keys also expose `new_wiping(...)`
constructors. These build the cipher, then erase the caller-provided key
buffer:

```rust
use cryptography::Aes256Ct;

let mut key = [0x42u8; 32];
let _cipher = Aes256Ct::new_wiping(&mut key);

assert_eq!(key, [0u8; 32]);
```

## How To Verify Correctness

Run the full suite:

```text
cargo test
```

Run one family:

```text
cargo test aes::tests
cargo test cast128::tests
cargo test camellia::tests
cargo test des::tests
cargo test grasshopper::tests
cargo test magma::tests
cargo test present::tests
cargo test serpent::tests
cargo test seed::tests
cargo test chacha20::tests
cargo test simon::tests
cargo test sm4::tests
cargo test speck::tests
cargo test twofish::tests
cargo test salsa20::tests
cargo test zuc::tests
cargo test public_key::
```

Coverage is in-module, not in separate test scripts. Each cipher family ships
its own known-answer vectors and fast-vs-`Ct` equivalence tests where both
paths exist.

The public-key tests cover raw arithmetic vectors, wrapper round-trips, RSA
OAEP/PSS behavior, DSA signing and verification, key serialization, and
OpenSSL interoperability checks where real standards exist.

The generic mode layer is covered in-module too:

```text
cargo test modes::tests
```

## How To Benchmark

The benchmark targets live in the separate `benchmarks/` crate so the root
package can run `cargo test` without pulling in benchmark-only dependencies.

Run the full suite throughput benchmark:

```text
cargo bench --manifest-path benchmarks/Cargo.toml --bench cipher_bench
```

Run the shorter host-comparison pass used in `ANALYSIS.md`:

```text
cargo bench --manifest-path benchmarks/Cargo.toml --bench cipher_bench -- \
  --sample-size 10 --measurement-time 0.2 --warm-up-time 0.1
```

Run the AES-focused comparison benchmark:

```text
cargo bench --manifest-path benchmarks/Cargo.toml --bench aes_bench
```

Run the public-key latency probe:

```text
cargo run --release --bin bench_public_key -- 1024
```

Unlike the symmetric-cipher Criterion benches, `bench_public_key` reports
latency for key generation and single encrypt/decrypt/sign/verify operations.

`aes_bench` compares the crate's AES implementations against libsodium
`secretbox`. This is a calibration benchmark, not a strict apples-to-apples
comparison: the crate's rows are raw AES block-cipher throughput, while the
libsodium row is a complete XSalsa20-Poly1305 authenticated-encryption
construction.

## Public-Key How To

The public-key module exposes three layers:

- core arithmetic primitives: `Rsa`, `Dsa`, `Cocks`, `ElGamal`, `Rabin`, `Paillier`, `SchmidtSamoa`
- shared arithmetic support: `BigUint`, `BigInt`, `MontgomeryCtx`
- usable wrappers:
  - `RsaOaep<H>` and `RsaPss<H>` for standards-based RSA encryption/signatures
  - standard RSA key externalization via PKCS #1 / PKCS #8 / SPKI in DER or PEM
  - crate-defined DER/PEM/XML key externalization for the non-RSA schemes, including `Dsa`
  - byte-to-byte encrypt/decrypt helpers for all implemented encryption-capable schemes
  - byte-to-byte sign/verify helpers for signature-capable schemes (`Dsa`, `RsaPss<H>`)
  - built-in key generation for all implemented public-key schemes
  - Paillier helper operations: ciphertext addition and rerandomization

Generate an RSA key pair from a CSPRNG:

```rust
use cryptography::{CtrDrbgAes256, Rsa};

let seed = [0x55u8; 48];
let mut drbg = CtrDrbgAes256::new(&seed);
let (public, private) = Rsa::generate(&mut drbg, 512).expect("RSA key");
```

Persist the RSA key pair in modern standard containers:

```rust
let private_pem = private.to_pkcs8_pem();
let public_pem = public.to_spki_pem();

let private_again =
    cryptography::RsaPrivateKey::from_pkcs8_pem(&private_pem).expect("PKCS #8");
let public_again =
    cryptography::RsaPublicKey::from_spki_pem(&public_pem).expect("SPKI");

assert_eq!(private_again, private);
assert_eq!(public_again, public);
```

If you want a simple human-readable export for debugging, RSA also has the same
flat XML convenience format as the non-RSA schemes:

```rust
let private_xml = private.to_xml();
let public_xml = public.to_xml();

let private_again = cryptography::RsaPrivateKey::from_xml(&private_xml).expect("xml");
let public_again = cryptography::RsaPublicKey::from_xml(&public_xml).expect("xml");

assert_eq!(private_again, private);
assert_eq!(public_again, public);
```

Persist a non-RSA key pair in the crate-defined portable format:

```rust
use cryptography::{CtrDrbgAes256, Paillier};

let mut drbg = CtrDrbgAes256::new(&[0x23; 48]);
let (public, private) = Paillier::generate(&mut drbg, 512).expect("Paillier key");

let public_pem = public.to_pem();
let private_pem = private.to_pem();

let public_again = cryptography::PaillierPublicKey::from_pem(&public_pem).expect("public");
let private_again = cryptography::PaillierPrivateKey::from_pem(&private_pem).expect("private");

assert_eq!(public_again, public);
assert_eq!(private_again, private);
```

The same non-RSA keys can also be exported as flat XML:

```rust
let public_xml = public.to_xml();
let private_xml = private.to_xml();

let public_again = cryptography::PaillierPublicKey::from_xml(&public_xml).expect("public");
let private_again = cryptography::PaillierPrivateKey::from_xml(&private_xml).expect("private");

assert_eq!(public_again, public);
assert_eq!(private_again, private);
```

Encrypt and decrypt with `RSAES-OAEP`:

```rust
use cryptography::{CtrDrbgAes256, RsaOaep, Sha1};

let mut drbg = CtrDrbgAes256::new(&[0x11; 48]);
// The OAEP label is an optional context string. The empty label is the
// standard default when you do not need domain separation.
let ciphertext =
    RsaOaep::<Sha1>::encrypt_rng(&public, b"", b"hello", &mut drbg).expect("OAEP");
let plaintext = RsaOaep::<Sha1>::decrypt(&private, b"", &ciphertext).expect("OAEP");

assert_eq!(plaintext, b"hello");
```

Sign and verify with `RSASSA-PSS`:

```rust
use cryptography::{CtrDrbgAes256, RsaPss, Sha256};

let mut drbg = CtrDrbgAes256::new(&[0x22; 48]);
let signature = RsaPss::<Sha256>::sign_rng(&private, b"message", &mut drbg).expect("PSS");
assert!(RsaPss::<Sha256>::verify(&public, b"message", &signature));
```

Generate and use a `DSA` key pair:

```rust
use cryptography::{CtrDrbgAes256, Dsa};

let mut drbg = CtrDrbgAes256::new(&[0x24; 48]);
let (public, private) = Dsa::generate(&mut drbg, 256).expect("DSA key");
let signature = private.sign_bytes(b"message digest", &mut drbg).expect("DSA sign");
assert!(public.verify_bytes(b"message digest", &signature));
```

Generate and use an `ElGamal` key pair:

```rust
use cryptography::{CtrDrbgAes256, ElGamal};

let mut drbg = CtrDrbgAes256::new(&[0x33u8; 48]);
let (public, private) = ElGamal::generate(&mut drbg, 256).expect("ElGamal key");
let ciphertext = public.encrypt_bytes(b"hi", &mut drbg).expect("message fits in F_p");
let plaintext = private.decrypt_bytes(&ciphertext).expect("valid ciphertext");

assert_eq!(plaintext, b"hi");
```

The other schemes follow the same pattern: the arithmetic primitive stays
available, and the usable layer exposes byte-to-byte helpers. `Paillier` also
keeps its homomorphic operations visible:

```rust
use cryptography::{BigUint, CtrDrbgAes256, Paillier};

let p = BigUint::from_u64(257);
let q = BigUint::from_u64(263);
let (public, private) = Paillier::from_primes(&p, &q).expect("Paillier key");
let mut drbg = CtrDrbgAes256::new(&[0x52u8; 48]);

let left = public.encrypt(b"\x12", &mut drbg).expect("message fits");
let right = public.encrypt(b"\x34", &mut drbg).expect("message fits");
let combined = public
    .add_ciphertexts(&left, &right)
    .expect("ciphertexts are in range");

assert_eq!(private.decrypt(&combined), b"\x46");
```

If you want the ciphertext as bytes instead of a scheme-native integer or
pair, use the dedicated byte-to-byte helpers:

```rust
let ciphertext = public
    .encrypt_bytes(b"\x2A", &mut drbg)
    .expect("message fits");
let plaintext = private.decrypt_bytes(&ciphertext).expect("valid ciphertext");
assert_eq!(plaintext, b"\x2A");
```

The same byte-oriented APIs work directly on file contents: read the file into
a byte buffer, call `encrypt_bytes` / `decrypt_bytes`, and write the returned
buffer back out. `RSA` is the only scheme with RFC/NIST message formatting
today; the other public-key schemes use explicit crate-defined wrappers and
serialization, which is documented in [ASYMMETRIC.md](ASYMMETRIC.md).

There is also a simple latency tool for the public-key layer:

```text
cargo run --release --bin bench_public_key -- 1024
```

Add `--skip-elgamal` if you only want RSA and Paillier timings and do not want
to wait for ElGamal parameter generation on larger inputs.

Pass a larger bit length (for example `2048`) to probe the current bigint
backend at practical sizes. This is the quickest way to decide whether the
in-tree bigint backend is still acceptable or whether it is time to swap to
`num-bigint`.

Generate a balanced dataset of raw samples:

```text
cargo run --release --bin gen_ml_dataset -- --output ml/data
```

For wider samples, pass `--sample-len`:

```text
cargo run --release --bin gen_ml_dataset -- --output ml/data --sample-len 256
```

Train the model in the local PyTorch virtualenv:

```text
ml/.venv-torch/bin/python ml/train_distinguisher.py --generate
```

The trainer exposes three architecture families:

- `cnn`: residual 1D CNN baseline
- `transformer`: patch Transformer for wider samples (`--patch-len` controls the patch width)
- `byte_transformer`: byte-level Transformer that attends over every byte token

It also exposes `--model-size base|large|xlarge` so you can scale the network
along with the dataset.

For example, a wider patch-Transformer run looks like:

```text
ml/.venv-torch/bin/python ml/train_distinguisher.py --generate \
  --sample-len 256 \
  --architecture transformer \
  --model-size large \
  --patch-len 16
```

And the byte-level Transformer path is:

```text
ml/.venv-torch/bin/python ml/train_distinguisher.py --generate \
  --sample-len 256 \
  --architecture byte_transformer \
  --model-size base
```

This writes the trained model and weights to `ml/out/`:

- `cipher_distinguisher.pt`
- `cipher_distinguisher_state_dict.pt`
- `labels.json`
- `metrics.json`
- `history.csv`

For the fuller ML workflow, including the adaptive overnight runner and dataset
auditing, see [ml/README.md](ml/README.md).

## ML Distinguisher Experiment

The repository also includes a PyTorch experiment under `ml/` for testing
whether a deep network can distinguish raw cipher output from chance.

The dataset uses only the fast cipher implementations. The `Ct` variants are
not separate classes because they should emit exactly the same bits as the fast
path for the same key and input.

## Design Notes

- No `unsafe`.
- No hardware AES intrinsics in the main AES implementation; keeping the core
  portable and safe matters on every processor family, not just the current
  benchmark host.
- No heap allocation inside block encrypt/decrypt paths.
- Benchmark and test coverage are tracked in [ANALYSIS.md](ANALYSIS.md).
- Reference PDFs used during implementation live in `pubs/`.

## Local PDFs

The `pubs/` directory now carries one or more local PDFs for every cipher
family and supporting primitive covered in this repository:

- AES: `fips197.pdf`, `boyar-peralta-2011-a-depth-16-circuit-for-the-aes-s-box.pdf`
- CAST-128 / CAST5: `rfc2144-cast128.pdf`
- Camellia: `camellia-specification.pdf`
- DES / 3DES: `fips46-3.pdf`, `nist-sp-800-67r2.pdf`
- PRESENT: `present-ches2007.pdf`
- Serpent: `serpent.pdf`
- Twofish: `twofish-paper.pdf`
- SEED: `rfc4009-seed-algorithm.pdf`, `rfc4196-seed-ipsec.pdf`
- SHA-1 / SHA-2: `fips180-4.pdf`
- SHA-3 / SHAKE: `fips202.pdf`
- HMAC: `fips198-1.pdf`
- DRBGs: `sp800-90a-r1.pdf`
- Public-key primitives and RSA standards: `cocks-1973-note-on-non-secret-encryption.pdf`, `rsa-1978.pdf`, `elgamal-1985.pdf`, `rabin-1979-digitalized-signatures-and-public-key-functions.pdf`, `paillier-1999.pdf`, `schmidt-samoa.pdf`, `rfc8017-pkcs1-v2_2.pdf`, `sp800-56b-r2.pdf`, `fips186-5.pdf`
- Modes of operation: `sp800-38a.pdf`, `sp800-38b.pdf`, `sp800-38d.pdf`, `sp800-38e.pdf`, `sp800-38f.pdf`, `rfc8452-aes-gcm-siv.pdf`
- SIMON / SPECK: `simon_speck_2013.pdf`
- Grasshopper: `rfc7801-kuznyechik.pdf`
- Magma: `rfc8891-magma.pdf`
- SM4: `sm4-linear-cryptanalysis-2024.pdf` (the official GM/T host is not reachable from this sandbox, so the checked-in local PDF is a public SM4-family paper)
- ChaCha20 / XChaCha20: `chacha-20080128.pdf`, `rfc8439-chacha20-poly1305.pdf`, `draft-irtf-cfrg-xchacha-03.pdf`
- Salsa20: `salsafamily-20071225.pdf`
- ZUC-128: `ts-135222-zuc.pdf`

## References

Local copies of implementation-specific papers live in `pubs/`. The
Boyar-Peralta AES S-box circuit paper is stored at
`pubs/boyar-peralta-2011-a-depth-16-circuit-for-the-aes-s-box.pdf`.

```bibtex
@misc{simon-speck-2013,
  author       = {Ray Beaulieu and Douglas Shors and Jason Smith and
                  Stefan Treatman-Clark and Bryan Weeks and Louis Wingers},
  title        = {The {SIMON} and {SPECK} Families of Lightweight Block Ciphers},
  howpublished = {{IACR} Cryptology ePrint Archive, Report 2013/404},
  year         = {2013},
  url          = {https://eprint.iacr.org/2013/404},
}

@techreport{fips197,
  author      = {{National Institute of Standards and Technology}},
  title       = {Advanced Encryption Standard ({AES})},
  institution = {National Institute of Standards and Technology},
  type        = {{Federal Information Processing Standard}},
  number      = {FIPS PUB 197},
  year        = {2001},
  month       = nov,
  url         = {https://csrc.nist.gov/publications/detail/fips/197/final},
}

@techreport{fips202,
  author      = {{National Institute of Standards and Technology}},
  title       = {{SHA}-3 Standard: Permutation-Based Hash and Extendable-Output Functions},
  institution = {National Institute of Standards and Technology},
  type        = {{Federal Information Processing Standard}},
  number      = {FIPS PUB 202},
  year        = {2015},
  month       = aug,
  url         = {https://csrc.nist.gov/pubs/fips/202/final},
}

@techreport{fips180-4,
  author      = {{National Institute of Standards and Technology}},
  title       = {Secure Hash Standard ({SHS})},
  institution = {National Institute of Standards and Technology},
  type        = {{Federal Information Processing Standard}},
  number      = {FIPS PUB 180-4},
  year        = {2015},
  month       = aug,
  url         = {https://csrc.nist.gov/pubs/fips/180-4/upd1/final},
}

@techreport{fips198-1,
  author      = {{National Institute of Standards and Technology}},
  title       = {The Keyed-Hash Message Authentication Code ({HMAC})},
  institution = {National Institute of Standards and Technology},
  type        = {{Federal Information Processing Standard}},
  number      = {FIPS PUB 198-1},
  year        = {2008},
  month       = jul,
  url         = {https://csrc.nist.gov/pubs/fips/198-1/final},
}

@techreport{fips186-5,
  author      = {{National Institute of Standards and Technology}},
  title       = {Digital Signature Standard ({DSS})},
  institution = {National Institute of Standards and Technology},
  type        = {{Federal Information Processing Standard}},
  number      = {FIPS PUB 186-5},
  year        = {2023},
  month       = feb,
  url         = {https://csrc.nist.gov/pubs/fips/186-5/final},
}

@misc{sp800-90a-r1,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Random Number Generation Using Deterministic Random Bit Generators},
  howpublished = {Special Publication 800-90A Revision 1},
  year         = {2015},
  month        = jun,
  url          = {https://csrc.nist.gov/pubs/sp/800/90/a/r1/final},
}

@misc{sp800-56b-r2,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography},
  howpublished = {Special Publication 800-56B Revision 2},
  year         = {2019},
  month        = mar,
  url          = {https://csrc.nist.gov/pubs/sp/800/56/b/r2/final},
}

@article{cocks-1973,
  author  = {Clifford Cocks},
  title   = {A Note on Non-Secret Encryption},
  journal = {{CESG} Research Memorandum},
  year    = {1973},
}

@article{rsa-1978,
  author  = {Ronald L. Rivest and Adi Shamir and Leonard Adleman},
  title   = {A Method for Obtaining Digital Signatures and Public-Key Cryptosystems},
  journal = {Communications of the ACM},
  volume  = {21},
  number  = {2},
  pages   = {120--126},
  year    = {1978},
  doi     = {10.1145/359340.359342},
}

@misc{rfc8017,
  author       = {K. Moriarty and B. Kaliski and J. Jonsson and A. Rusch},
  title        = {{PKCS} \#1: RSA Cryptography Specifications Version 2.2},
  howpublished = {RFC 8017},
  year         = {2016},
  month        = nov,
  doi          = {10.17487/RFC8017},
  url          = {https://www.rfc-editor.org/rfc/rfc8017},
}

@article{elgamal-1985,
  author  = {Taher ElGamal},
  title   = {A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms},
  journal = {{IEEE} Transactions on Information Theory},
  volume  = {31},
  number  = {4},
  pages   = {469--472},
  year    = {1985},
  doi     = {10.1109/TIT.1985.1057074},
}

@article{rabin-1979,
  author  = {Michael O. Rabin},
  title   = {Digitalized Signatures and Public-Key Functions as Intractable as Factorization},
  journal = {MIT Laboratory for Computer Science Technical Report},
  number  = {MIT/LCS/TR-212},
  year    = {1979},
}

@inproceedings{paillier-1999,
  author    = {Pascal Paillier},
  title     = {Public-Key Cryptosystems Based on Composite Degree Residuosity Classes},
  booktitle = {Advances in Cryptology --- EUROCRYPT '99},
  series    = {Lecture Notes in Computer Science},
  volume    = {1592},
  pages     = {223--238},
  year      = {1999},
  publisher = {Springer},
  doi       = {10.1007/3-540-48910-X_16},
}

@inproceedings{schmidt-samoa-2005,
  author    = {Katja Schmidt-Samoa},
  title     = {A New Rabin-Type Trapdoor Permutation Equivalent to Factoring},
  booktitle = {Electronic Notes in Theoretical Computer Science},
  volume    = {157},
  pages     = {79--94},
  year      = {2006},
  publisher = {Elsevier},
  doi       = {10.1016/j.entcs.2005.11.052},
}

@misc{sp800-38a,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Block Cipher Modes of Operation: Methods and Techniques},
  howpublished = {Special Publication 800-38A},
  year         = {2001},
  month        = dec,
  url          = {https://csrc.nist.gov/pubs/sp/800/38/a/final},
}

@misc{sp800-38b,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Block Cipher Modes of Operation: The {CMAC} Mode for Authentication},
  howpublished = {Special Publication 800-38B},
  year         = {2005},
  month        = may,
  url          = {https://csrc.nist.gov/pubs/sp/800/38/b/final},
}

@misc{sp800-38d,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode ({GCM}) and {GMAC}},
  howpublished = {Special Publication 800-38D},
  year         = {2007},
  month        = nov,
  url          = {https://csrc.nist.gov/pubs/sp/800/38/d/final},
}

@misc{sp800-38e,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Block Cipher Modes of Operation: The {XTS}-{AES} Mode for Confidentiality on Storage Devices},
  howpublished = {Special Publication 800-38E},
  year         = {2010},
  month        = jan,
  url          = {https://csrc.nist.gov/pubs/sp/800/38/e/final},
}

@misc{sp800-38f,
  author       = {{National Institute of Standards and Technology}},
  title        = {Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping},
  howpublished = {Special Publication 800-38F},
  year         = {2012},
  month        = dec,
  url          = {https://csrc.nist.gov/pubs/sp/800/38/f/final},
}

@techreport{rfc8452,
  author      = {S. Gueron and A. Langley and Y. Lindell},
  title       = {{AES}-{GCM}-{SIV}: Nonce Misuse-Resistant Authenticated Encryption},
  type        = {{RFC}},
  number      = {8452},
  institution = {IETF},
  year        = {2019},
  month       = apr,
  url         = {https://www.rfc-editor.org/rfc/rfc8452},
}

@misc{boyar-peralta-2011,
  author       = {Joan Boyar and Ren{\'e} Peralta},
  title        = {A depth-16 circuit for the {AES} {S}-box},
  howpublished = {{IACR} Cryptology ePrint Archive, Report 2011/332},
  year         = {2011},
  url          = {https://eprint.iacr.org/2011/332},
}

@techreport{fips46-3,
  author      = {{National Institute of Standards and Technology}},
  title       = {Data Encryption Standard ({DES})},
  institution = {National Institute of Standards and Technology},
  type        = {{Federal Information Processing Standard}},
  number      = {FIPS PUB 46-3},
  year        = {1999},
  month       = oct,
  url         = {https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25},
}

@techreport{rfc2144,
  author      = {C. Adams},
  title       = {The CAST-128 Encryption Algorithm},
  type        = {{RFC}},
  number      = {2144},
  institution = {IETF},
  year        = {1997},
  month       = may,
  url         = {https://www.rfc-editor.org/rfc/rfc2144},
}

@inproceedings{anderson-biham-knudsen-1998-serpent,
  author    = {Ross Anderson and Eli Biham and Lars Knudsen},
  title     = {Serpent: A Proposal for the Advanced Encryption Standard},
  booktitle = {Fast Software Encryption --- FSE 1998},
  editor    = {Alfred J. Menezes},
  series    = {Lecture Notes in Computer Science},
  volume    = {1372},
  pages     = {222--238},
  publisher = {Springer},
  year      = {1998},
  doi       = {10.1007/3-540-69710-1_15},
  url       = {https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf},
}

@misc{twofish-1998,
  author       = {Bruce Schneier and John Kelsey and Doug Whiting and
                  David Wagner and Chris Hall and Niels Ferguson},
  title        = {Twofish: A 128-Bit Block Cipher},
  howpublished = {AES submission / design paper},
  year         = {1998},
  url          = {https://www.schneier.com/wp-content/uploads/2016/02/paper-twofish-paper.pdf},
}

@misc{camellia-spec,
  author       = {Kazumaro Aoki and Takeshi Ichikawa and Masayuki Kanda and
                  Mitsuru Matsui and Shiho Moriai and Junko Nakajima and
                  Toshio Tokita},
  title        = {Specification of Camellia, a 128-bit Block Cipher},
  howpublished = {CRYPTREC submission / algorithm specification},
  year         = {2001},
  url          = {https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/06_01espec.pdf},
}

@techreport{rfc3713,
  author      = {Mitsuru Matsui and Junko Nakajima and Shiho Moriai},
  title       = {A Description of the Camellia Encryption Algorithm},
  type        = {{RFC}},
  number      = {3713},
  institution = {IETF},
  year        = {2004},
  month       = apr,
  url         = {https://www.rfc-editor.org/rfc/rfc3713},
}

@techreport{rfc4312,
  author      = {K. Seo and S. Kent},
  title       = {Camellia Encryption Algorithm Use with IPsec},
  type        = {{RFC}},
  number      = {4312},
  institution = {IETF},
  year        = {2005},
  month       = dec,
  url         = {https://www.rfc-editor.org/rfc/rfc4312},
}

@techreport{rfc4009,
  author      = {Jongwook Park and Sungjae Lee and Jeeyeon Kim and Jaeil Lee},
  title       = {The {SEED} Encryption Algorithm},
  type        = {{RFC}},
  number      = {4009},
  institution = {IETF},
  year        = {2005},
  month       = feb,
  url         = {https://www.rfc-editor.org/rfc/rfc4009},
}

@techreport{rfc4196,
  author      = {Hyangjin Lee and Jaeho Yoon and Seoklae Lee and Jaeil Lee},
  title       = {The {SEED} Cipher Algorithm and Its Use with {IPsec}},
  type        = {{RFC}},
  number      = {4196},
  institution = {IETF},
  year        = {2005},
  month       = oct,
  url         = {https://www.rfc-editor.org/rfc/rfc4196},
}

@techreport{sp800-67r2,
  author      = {{National Institute of Standards and Technology}},
  title       = {Recommendation for the Triple Data Encryption Algorithm
                 ({TDEA}) Block Cipher},
  institution = {National Institute of Standards and Technology},
  type        = {{NIST Special Publication}},
  number      = {800-67 Revision 2},
  year        = {2017},
  month       = nov,
  url         = {https://csrc.nist.gov/publications/detail/sp/800-67/rev-2/final},
}

@book{daemen-rijmen-2002,
  author    = {Joan Daemen and Vincent Rijmen},
  title     = {The Design of {Rijndael}: {AES} --- The Advanced Encryption Standard},
  publisher = {Springer},
  year      = {2002},
  isbn      = {978-3-540-42580-9},
}

@techreport{rfc7801,
  author      = {V. Dolmatov},
  title       = {GOST R 34.12-2015: Block Cipher ``Grasshopper''},
  type        = {{RFC}},
  number      = {7801},
  institution = {IETF},
  year        = {2016},
  month       = mar,
  url         = {https://www.rfc-editor.org/rfc/rfc7801},
}

@techreport{rfc8891,
  author      = {V. Dolmatov and A. Degtyarev},
  title       = {GOST R 34.12-2015: Block Cipher ``Magma''},
  type        = {{RFC}},
  number      = {8891},
  institution = {IETF},
  year        = {2020},
  month       = sep,
  url         = {https://www.rfc-editor.org/rfc/rfc8891},
}

@inproceedings{bogdanov-2007-present,
  author    = {Andrey Bogdanov and Lars R. Knudsen and Gregor Leander and
               Christof Paar and Axel Poschmann and Matthew J. B. Robshaw and
               Yannick Seurin and Charlotte Vikkelsoe},
  title     = {{PRESENT}: An Ultra-Lightweight Block Cipher},
  booktitle = {Cryptographic Hardware and Embedded Systems --- {CHES} 2007},
  year      = {2007},
  pages     = {450--466},
  publisher = {Springer},
  url       = {https://crypto.orange-labs.fr/papers/ches2007-450.pdf},
}

@techreport{gm-t-0002-2012,
  author      = {{State Cryptography Administration of the People's Republic of China}},
  title       = {{SM4} Block Cipher Algorithm},
  institution = {{State Cryptography Administration of the People's Republic of China}},
  type        = {{GM/T}},
  number      = {0002-2012},
  year        = {2012},
  month       = mar,
  url         = {https://www.gmbz.org.cn/upload/2025-01-23/1737625646289030731.pdf},
  note        = {English translation of the Chinese standard},
}

@article{liu-2024-sm4-linear,
  author  = {Qi Liu and others},
  title   = {Linear Cryptanalysis of {SM4} based on Correlation of Binary Masks},
  journal = {Highlights in Science, Engineering and Technology},
  volume  = {83},
  pages   = {17--22},
  year    = {2024},
  url     = {https://zenodo.org/records/10867006/files/_3_219_17-22_Liu.pdf?download=1},
}

@techreport{etsi-sage-zuc-v16,
  author      = {{ETSI SAGE}},
  title       = {Specification of the 3GPP Confidentiality and Integrity Algorithms
                 128-{EEA3} \& 128-{EIA3}; Document 2: {ZUC} Specification},
  institution = {{European Telecommunications Standards Institute}},
  type        = {Specification},
  version     = {1.6},
  year        = {2011},
  note        = {Referenced by 3GPP TS 35.222 / ETSI TS 135 222},
  url         = {https://www.etsi.org/deliver/etsi_ts/135200_135299/135222/16.00.00_60/ts_135222v160000p.pdf},
}

@incollection{salsafamily-2007,
  author    = {Daniel J. Bernstein},
  title     = {The {Salsa20} family of stream ciphers},
  booktitle = {New Stream Cipher Designs},
  series    = {Lecture Notes in Computer Science},
  volume    = {4986},
  pages     = {84--97},
  publisher = {Springer},
  year      = {2008},
  note      = {Author's specification PDF dated 2007-12-25},
  url       = {https://cr.yp.to/snuffle/salsafamily-20071225.pdf},
}

@misc{chacha-2008,
  author       = {Daniel J. Bernstein},
  title        = {ChaCha, a variant of Salsa20},
  howpublished = {Author's specification paper},
  year         = {2008},
  month        = jan,
  url          = {https://cr.yp.to/chacha/chacha-20080128.pdf},
}

@techreport{rfc8439,
  author      = {Y. Nir and A. Langley},
  title       = {ChaCha20 and Poly1305 for {IETF} Protocols},
  type        = {{RFC}},
  number      = {8439},
  institution = {IETF},
  year        = {2018},
  month       = jun,
  url         = {https://www.rfc-editor.org/rfc/rfc8439},
}

@misc{draft-irtf-cfrg-xchacha-03,
  author       = {A. Langley and Y. Nir},
  title        = {{XChaCha}: eXtended-nonce ChaCha and {AEAD}\_XChaCha20\_Poly1305},
  howpublished = {Internet-Draft, draft-irtf-cfrg-xchacha-03},
  year         = {2020},
  month        = jan,
  url          = {https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt},
  note         = {Local PDF copy in `pubs/` generated from the IETF draft text},
}
```
