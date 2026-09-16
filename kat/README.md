# NTRU round-3 known-answer files

These four files are the known-answer test (KAT) files published in the NIST
Post-Quantum Cryptography Round 3 submission package for NTRU,
`NTRU-Round3.zip` (top directory `NIST-PQ-Submission-NTRU-20201016`), from
<https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/NTRU-Round3.zip>.
They are copied unmodified; the SHA-256 digests below match the files inside
the package's `KAT/` directory. They are test data, not code, and they are
the external evidence that `src/public_key/ntru_hps*.rs` and
`src/public_key/ntru_hrss701.rs` produce the submission's keys, ciphertexts,
and shared secrets.

The specification those files accompany is the package's
`Supporting_Documentation/ntru.pdf`, kept here as
`pubs/ntru-round3-specification.pdf`.

Each per-set test module replays its file through the public API (key
generation from the entry's seed through `CtrDrbgAes256`, encapsulation,
decapsulation) and compares `pk`, `sk`, `ct` and `ss` byte for byte. The
default test `nist_kat` replays counts 0, 1, 7, 23, 42, 67, 83 and 99 in a
debug build and all 100 counts in a release build; `nist_kat_full` replays all
100 counts in any build and is run with `cargo test --lib ntru -- --ignored`.

| File in this directory | Path inside the package | SHA-256 |
|---|---|---|
| `ntruhps509.rsp` | `KAT/ntruhps2048509/PQCkemKAT_935.rsp` | `f85cbfd585ee9e03feb10817f7a4ba42695a67af95db383c5ebbc2beab27e6bc` |
| `ntruhps677.rsp` | `KAT/ntruhps2048677/PQCkemKAT_1234.rsp` | `0e1d2eccfbc6e4f4d6f139b21de27417316202a5c113602d25704316aebb9303` |
| `ntruhps821.rsp` | `KAT/ntruhps4096821/PQCkemKAT_1590.rsp` | `95235f04c6206a82477fd5a877f184e99906d658a242dcd7ebb8337048129a4b` |
| `ntruhrss701.rsp` | `KAT/ntruhrss701/PQCkemKAT_1450.rsp` | `1e7c8e02f7dc1a9796332d60d1b08995fff5dfe81f2ae7394ec2f4816dedf4b6` |
