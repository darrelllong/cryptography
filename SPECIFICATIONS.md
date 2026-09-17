# What each algorithm implements, and what checks it

Every scheme in this crate is written from a published specification. This file
says, for each one, which document and which part of it, where its known answers
come from, and which tests refuse malformed input. It separates three claims the
reviews ask to keep apart:

- **conformance to a specification**, which the specification's own published
  answers check;
- **interoperability**, which agreement with another implementation checks;
- **refusal**, which tests of malformed, out-of-range and degenerate input check.

A passing known-answer test says the algorithm computes the right function on
the inputs the document lists. It says nothing about inputs the document does
not list, about timing, or about a scheme's security in a protocol.

Tests named without a file are unit tests in the named module; `tests/…` names
are integration tests. Vector files live in `tests/vectors/` and carry their
source in a header comment.

## Block and stream ciphers

| Algorithm | Specification | Known answers | Refusals and limits |
|---|---|---|---|
| AES-128/192/256 | FIPS 197 | `fips197_appendix_c1_aes128`, `…c2_aes192`, `…c3_aes256`, `fips197_appendix_a1_key_expansion`; `aes_matches_openssl_ecb` | `block_cipher_trait_refuses_wrong_block_length` |
| Camellia-128/192/256 | RFC 3713 (ISO/IEC 18033-3) | `camellia128_kat`, `camellia192_kat`, `camellia256_kat`, and the `Ct` twins | `block_cipher_trait_refuses_wrong_block_length` |
| CAST-128 | RFC 2144 §A | `cast128_128bit_kat`, `cast128_80bit_kat`, `cast128_40bit_kat` | `key_length_below_range_rejected`, `key_length_above_range_rejected`, `empty_key_rejected` |
| DES, Triple-DES | FIPS 46-3, SP 800-67 Rev. 2 | `tdes_3key_sp800_67_appendix_b_kat`, CAVP `KAT_TDES` tables, `des_matches_openssl_ecb` | weak and semi-weak keys refused, repeated key components refused, `block_cipher_trait_refuses_short_block` |
| Kuznyechik | RFC 7801 (GOST R 34.12-2015) | `s_vectors`, `r_vectors`, `l_vectors`, `encrypt_decrypt_rfc` | `block_cipher_rejects_wrong_length` |
| Magma | RFC 8891 (GOST R 34.12-2015) | `t_vectors`, `g_vectors`, `key_schedule_vectors` | `block_cipher_rejects_wrong_length` |
| PRESENT-80/128 | Bogdanov et al., CHES 2007 (ISO/IEC 29192-2) | `present80_kats`, `present128_kats`, and the `Ct` twins | `block_cipher_rejects_wrong_length` |
| Rabbit | RFC 4503 | `rfc4503_appendix_a1_without_iv_setup`, `rfc4503_appendix_a2_with_iv_setup` | `new_wiping_zeroes_inputs_and_matches_new` |
| Salsa20 | Bernstein's Salsa20 specification; eSTREAM vectors | `salsa20_128bit_estream_set1_vector0`, `salsa20_256bit_estream_set1_vector0` | `counter_carries_across_the_32_bit_boundary` |
| SEED | RFC 4269 | `round_keys_match_rfc4269_appendix_b1`, `seed_kats`, `seed_matches_openssl_ecb` | `block_cipher_rejects_wrong_length` |
| Serpent-128/192/256 | AES submission (Anderson, Biham, Knudsen) | `serpent128_standard_byte_order_vector`, `submission_variable_key_vectors` | `block_cipher_rejects_wrong_length` |
| SIMON | Beaulieu et al., "The SIMON and SPECK Families of Lightweight Block Ciphers" | `simon32_64_kat`, `simon48_72_kat`, `simon64_128_kat`, … | `block_cipher_rejects_wrong_length` |
| SPECK | the same paper | `speck32_64_kat`, `speck48_72_kat`, `speck48_96_kat`, … | `block_cipher_rejects_wrong_length` |
| SM4 | GM/T 0002-2012 (GB/T 32907-2016) | `sm4_matches_openssl_ecb`, `sm4_and_sm4ct_match_random_vectors` | `block_cipher_rejects_wrong_length` |
| Twofish-128/192/256 | AES submission (Schneier et al.) | submission vectors in `twofish::tests` | `block_cipher_rejects_wrong_length` |
| ChaCha20, XChaCha20 | RFC 8439 §2.3; draft-irtf-cfrg-xchacha-03 | `chacha20_rfc8439_block1_vector`, `hchacha20_draft_vector`, `tests/kat_rfc8439.rs`, `tests/kat_xchacha20.rs` | `keystream_past_the_last_block_panics`, `xchacha20_past_the_last_block_panics` |
| SNOW 3G | ETSI/SAGE UEA2 & UIA2 specification | the specification's test sets in `snow3g::tests` | `next_word_discards_and_wipes_pending_bytes` |
| ZUC-128 | ETSI/SAGE 128-EEA3 & 128-EIA3 specification | the specification's test sets in `zuc::tests` | `next_word_discards_and_wipes_pending_bytes` |

## Hashes, MACs and key derivation

| Algorithm | Specification | Known answers | Refusals and limits |
|---|---|---|---|
| SHA-1, SHA-2 family | FIPS 180-4 | `tests/kat_hash.rs` (NIST "Examples with Intermediate Values"), padding-boundary checks against OpenSSL | — |
| SHA-3, SHAKE | FIPS 202 | `tests/kat_hash.rs`, padding-edge checks against OpenSSL; round constants, ρ and π recomputed from their definitions | — |
| MD5 | RFC 1321 | RFC 1321 §A.5 digests in `md5::tests` (`md5_empty`, `md5_streaming_abc`, `md5_known_vector`), `md5_matches_openssl`; the `T` table recomputed from `⌊2³² |sin i|⌋` | — |
| RIPEMD-160 | Dobbertin, Bosselaers, Preneel, "RIPEMD-160: A Strengthened Version of RIPEMD" | the paper's test suite in `ripemd160::tests` (`ripemd160_empty`, `ripemd160_abc`, `ripemd160_message_digest`, …) | — |
| HMAC | FIPS 198-1, RFC 2104 | `tests/kat_hmac_cmac.rs` (RFC 4231, RFC 2202) | `hmac_*_verify_refuses_every_wrong_tag` (every flipped bit, prefix, wrong key or message) |
| CMAC | SP 800-38B | `tests/kat_hmac_cmac.rs`, the SP 800-38B examples for AES-128/192/256 and TDEA (`cmac_aes128_example_3`, …) | 64-bit and 128-bit blocks only |
| HKDF | RFC 5869 | `rfc5869_case_1_sha256` through `rfc5869_case_7_sha1_no_salt` | `expand_rejects_overlong_output` (255·HashLen) |

## Modes and authenticated encryption

| Mode | Specification | Known answers | Refusals and limits |
|---|---|---|---|
| CTR, CBC, CFB, OFB, ECB | SP 800-38A | mode examples in `modes::tests`, cross-checked against OpenSSL | padding and length rules per mode |
| GCM, GMAC | SP 800-38D | `tests/kat_gcm.rs` (McGrew–Viega, the submission SP 800-38D cites) | payload and AAD bounds of §5.2.1.1, tag refusal on every perturbation |
| GCM-SIV | RFC 8452 | `tests/kat_rfc8452_gcm_siv.rs` (Appendix C) | nonce and length rules, tag refusal |
| CCM | SP 800-38C | `tests/kat_ccm.rs` (SP 800-38C and RFC 3610) | nonce 7–13 bytes, tag in {4,6,…,16}, refusal on perturbation |
| OCB3 | RFC 7253 | `tests/kat_rfc7253_ocb.rs` (Appendix A, every AES parameter set) | nonce at most 120 bits, tag lengths 128/96/64 |
| EAX | Bellare, Rogaway, Wagner, "A Conventional Authenticated-Encryption Mode" (ePrint 2003/069) | `eax_aes128_eprint_2003_069_known_vectors` | `eax_tamper_rejected`; 128-bit block ciphers only |
| SIV | RFC 5297 | `rfc5297_a1_deterministic_vector`, `rfc5297_a2_nonce_based_vector` | at most 126 associated-data components, 2³⁹−128 bit plaintext |
| XTS | SP 800-38E (IEEE Std 1619-2007) | `xts_aes128_ieee1619_annex_b_vectors` | data unit at least one block, at most 2²⁰ blocks |
| AES key wrap | RFC 3394 | `aes_key_wrap_rfc3394_4_1` through `…_4_6` | minimum wrapped lengths, integrity check on unwrap |
| Poly1305 | RFC 8439 §2.5 | `tests/kat_rfc8439.rs`, the §2.5.2 example | one-time key discipline documented; `verify` is constant-time |
| ChaCha20-Poly1305 | RFC 8439 §2.8 | `tests/kat_rfc8439.rs` (Appendix A) | 2³⁸−64 byte plaintext bound, tag refusal |
| GHASH, POLYVAL | SP 800-38D §6.3, RFC 8452 §3 | field vectors in `ghash::tests`, the GCM and GCM-SIV suites | constant-time selection over the multiples table |

## Deterministic generators

| Generator | Specification | Known answers | Refusals and limits |
|---|---|---|---|
| CTR_DRBG (AES-256, no df) | SP 800-90A Rev. 1 §10.2.1 | `tests/kat_ctr_drbg.rs` (CAVP, 120 trials, both AES paths) | request and reseed-interval bounds, additional input at most seedlen |
| Hash_DRBG (SHA-256) | SP 800-90A Rev. 1 §10.1.1 | `tests/kat_hash_hmac_drbg.rs` (CAVP, 120 trials) | `ReseedRequired`, `RequestTooLarge`, `InputTooShort`; one Generate per call |
| HMAC_DRBG (SHA-256) | SP 800-90A Rev. 1 §10.1.2 | `tests/kat_hash_hmac_drbg.rs` (CAVP, 120 trials) | the same three refusals |
| Fast key erasure | Bernstein, "Fast-key-erasure random-number generators" (2017) | `first_refills_match_openssl_chacha20` | served bytes erased, no process identity, reseed discards unserved bytes |

## Public-key schemes

| Scheme | Specification | Known answers | Refusals and limits |
|---|---|---|---|
| RSA primitive | Rivest–Shamir–Adleman (1978); RFC 8017 §3 key shapes | key derivation and CRT checks in `rsa::tests` | RFC 8017 exponent ranges, CRT fault check, blinding |
| RSAES-OAEP, RSASSA-PSS, PKCS #1 v1.5 | RFC 8017 §7.1, §8.1, §8.2 | RFC 8017 test vectors in `rsa_pkcs1::tests` | modulus floors, salt and label rules, decoding refusals |
| DSA | FIPS 186-4 | `tests/kat_fips186_dsa.rs` (CAVP key pairs, siggen, sigver), `tests/kat_rfc6979.rs` | domain-parameter validation, nonce draw bound, refusal of `r` or `s` = 0 |
| Diffie-Hellman | SP 800-56A Rev. 3 §5.7.1.1 | `tests/kat_kas_ffc.rs` (CAVP KAS FFC) | partial public-key validation, small-subgroup refusal |
| ECDSA | FIPS 186-5 (SEC 1 v2.0 arithmetic) | `tests/kat_rfc6979.rs` (deterministic vectors), CAVP-style checks in `ecdsa::tests` | identity and off-curve keys refused, high-`s` accepted on verify, strict and BER DER decoders |
| ECDH | SP 800-56A Rev. 3, RFC 5903 | `tests/kat_rfc5903_ecdh.rs` (§8, three curves) | peer-curve mismatch, identity and invalid points refused |
| X25519, X448 | RFC 7748 §5, §6 | `tests/kat_rfc7748.rs`, including the million-iteration cases (release-only) | all-zero shared secret refused; constant-time ladder |
| Ed25519 | RFC 8032 §5.1 | RFC 8032 §7.1 vectors in `ed25519::tests` | decoding exactly per §5.1.3, cofactored verification, small-order keys accepted and documented |
| EdDSA (generic Edwards) | Schnorr/EdDSA construction over this crate's Edwards arithmetic | round-trip and cross-checks in `eddsa::tests` | curve and order validation, identity refusal |
| ECIES | SEC 1 v2.0 §5.1 | GEC 2 vectors in `tests/vectors/sec1_gec2_ecaes.txt` | key-derivation and MAC rules, ciphertext refusal |
| EC-ElGamal, Edwards ElGamal | ElGamal's map over curve groups (this crate's profile) | round-trip and homomorphism tests | identity and off-curve points refused; message class published (documented) |
| ElGamal (finite field) | ElGamal (1985) | small-modulus vectors in `elgamal::tests` | safe prime and primitive root required, degenerate nonce and secret refused |
| Paillier | Paillier (1999) | homomorphic identities in `paillier::tests` | modulus and base validation |
| Rabin | Rabin (1979), with a tag to select the root | round-trip and root-selection tests | four-root ambiguity resolved by tag; refusal on tampering |
| Schmidt-Samoa | Schmidt-Samoa (2005) | round-trip tests | prime and modulus validation |
| Cocks | Cocks, CESG memorandum (1973) | round-trip tests | prime validation, `pi` invertibility |
| ML-KEM | FIPS 203 | `tests/vectors/ml_kem_acvp_fips203.txt` (NIST ACVP), pq-crystals oracle vectors | §7.2 and §7.3 key checks, pair-wise test on seedless import, implicit rejection |
| ML-DSA | FIPS 204 | `tests/vectors/ml_dsa_fips204_subset.txt` (ACVP keyGen, sigGen, sigVer) | expanded-key consistency, range checks, hedged and deterministic paths |
| NTRU (round 3) | NIST round-3 submission, "NTRU: Algorithm Specifications and Supporting Documentation" | the four submission KAT files, 100 entries each (release-only) | zero polynomials refused, sampler bounds, implicit rejection |
| NTRUEncrypt SVES-3 | EESS #1 v3.1 (IEEE Std 1363.1-2008 / ANSI X9.98 sets) | `tests/vectors/ntru_ees_sves3_reference.txt` (interoperability with the standard authors' implementation) | step p refusal rates measured, `dm0` pinned two ways, canonical encoding enforced; parameter sources are tabulated in the `ntru_ees_core` module documentation |

## Key encodings

| Encoding | Specification | Known answers | Refusals and limits |
|---|---|---|---|
| `SubjectPublicKeyInfo`, `OneAsymmetricKey` | RFC 5280 §4.1, RFC 5958 | OpenSSL cross-checks in `pkix::tests` | strict DER entry points, BER receivers beside them |
| PEM | RFC 7468 | round-trip and OpenSSL checks | label and line rules; BER contents accepted per §13 |
| RSA keys | RFC 8017 Appendix A, RFC 3279 §2.3.1 | OpenSSL cross-checks in `rsa_io::tests` | `NULL` parameters required, φ-reduced `d` accepted |
| EC keys | RFC 5480, RFC 5915 | OpenSSL cross-checks in `ec_pkix::tests` | named curves only on import, explicit parameters validated per SEC 1 §3.1.1.2.1 |
| DSA and DH keys | RFC 3279 §2.3.2, §2.3.3 | OpenSSL cross-checks in `ffc_pkix::tests` | domain-parameter validation |
| X25519, X448, Ed25519 keys | RFC 8410 | RFC 8410 §10 examples | fixed lengths, absent parameters required |
| ML-KEM, ML-DSA keys | RFC 9935 §6, RFC 9881 §6 | the RFCs' Appendix C examples | seed and expanded-key forms, consistency checks |
| Crate-defined blobs, PEM and XML | this crate | round-trip tests per scheme | field count and range checks before any arithmetic |
