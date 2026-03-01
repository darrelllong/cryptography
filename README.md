# cryptography

Pure, safe, portable Rust implementations of classical and modern ciphers
written directly from the published specifications.

Implemented families:

- DES and Triple-DES
- AES (`Aes128/192/256`) plus software constant-time variants (`Aes*Ct`)
- Camellia (`Camellia128/192/256`) plus software constant-time variants
- SEED plus `SeedCt`
- SIMON (all 10 published variants)
- SPECK (all 10 published variants)
- PRESENT (`Present80` / `Present128`) plus software constant-time variants
- Magma plus `MagmaCt`
- Grasshopper plus `GrasshopperCt`
- SM4 / SMS4 plus `Sm4Ct`
- ZUC-128 plus `Zuc128Ct`

See [ANALYSIS.md](ANALYSIS.md) for algorithm notes, coverage, and the current
benchmark numbers for this host.

## HOWTO

### Generic block-cipher example

All block ciphers implement the shared `BlockCipher` trait for in-place
operation on a mutable byte slice:

```rust
use cryptography::{Aes128, BlockCipher};

let cipher = Aes128::new(&[0u8; 16]);
let mut block = [0u8; 16];

cipher.encrypt(&mut block);
cipher.decrypt(&mut block);
```

### Fixed-size block example

Each block cipher type also exposes typed helpers when the block size is known
at compile time:

```rust
use cryptography::Sm4;

let cipher = Sm4::new(&[0u8; 16]);
let block = [0u8; 16];

let ct = cipher.encrypt_block(&block);
let pt = cipher.decrypt_block(&ct);
assert_eq!(pt, block);
```

### Constant-time example

If you need the software constant-time path, use the dedicated `Ct` type:

```rust
use cryptography::Aes128Ct;

let cipher = Aes128Ct::new(&[0u8; 16]);
let block = [0u8; 16];

let ct = cipher.encrypt_block(&block);
let pt = cipher.decrypt_block(&ct);
assert_eq!(pt, block);
```

### Stream-cipher example

ZUC produces keystream words and can fill a caller-supplied buffer:

```rust
use cryptography::Zuc128;

let mut buf = [0u8; 64];
let zuc = Zuc128::new(&[0u8; 16], &[0u8; 16]);

zuc.fill(&mut buf);
```

### Fast vs `Ct` variants

For AES, DES, Magma, Grasshopper, SM4, and ZUC, the default type is the fast
software implementation and the `Ct` type is the separate constant-time
software path.

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
cargo test camellia::tests
cargo test des::tests
cargo test grasshopper::tests
cargo test magma::tests
cargo test present::tests
cargo test seed::tests
cargo test simon::tests
cargo test sm4::tests
cargo test speck::tests
cargo test zuc::tests
```

Coverage is in-module, not in separate test scripts. Each cipher family ships
its own known-answer vectors and fast-vs-`Ct` equivalence tests where both
paths exist.

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

`aes_bench` compares the crate's AES implementations against libsodium. It
requires a working `libsodium` installation. This is a calibration benchmark,
not a strict apples-to-apples comparison: the crate's rows are raw AES block
cipher throughput, while the libsodium `secretbox` rows are a complete
XSalsa20-Poly1305 authenticated-encryption construction. The libsodium
AES-256-GCM row, when available, is also an AEAD and is feature-detected at
runtime, so it may be skipped if `sodiumoxide` reports that hardware AES is
unavailable.

## ML Distinguisher Experiment

The repository also includes a PyTorch experiment under `ml/` for testing
whether a deep network can distinguish raw cipher output from chance.

The dataset uses only the fast cipher implementations. The `Ct` variants are
not separate classes because they should emit exactly the same bits as the fast
path for the same key and input.

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

The trainer also exposes `--model-size base|large|xlarge` so you can scale the
network along with the dataset.

This writes the trained model and weights to `ml/out/`:

- `cipher_distinguisher.pt`
- `cipher_distinguisher_state_dict.pt`
- `labels.json`
- `metrics.json`
- `history.csv`

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
family covered in this repository:

- AES: `fips197.pdf`, `boyar-peralta-2011-a-depth-16-circuit-for-the-aes-s-box.pdf`
- Camellia: `camellia-specification.pdf`
- DES / 3DES: `fips46-3.pdf`, `nist-sp-800-67r2.pdf`
- PRESENT: `present-ches2007.pdf`
- SEED: `rfc4009-seed-algorithm.pdf`, `rfc4196-seed-ipsec.pdf`
- SIMON / SPECK: `simon_speck_2013.pdf`
- Grasshopper: `rfc7801-kuznyechik.pdf`
- Magma: `rfc8891-magma.pdf`
- SM4: `sm4-linear-cryptanalysis-2024.pdf` (the official GM/T host is not reachable from this sandbox, so the checked-in local PDF is a public SM4-family paper)
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
```
