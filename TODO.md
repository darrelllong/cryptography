# TODO

The work queue. The outside review's findings are in `AUDIT.md` and its
proposals in `SUGGESTIONS.md`; this file lists only what is still to be done.
Items are marked **owner** when only the repository owner can do them.

## Publication and history

1. **Published releases carry the pre-audit code (owner).** The crates.io API
   on 2026-09-16 lists 0.5.0, 0.6.0, 0.6.1 and 0.6.2, none yanked; docs.rs
   serves the same sources. Yank them, and request deletion where crates.io
   policy allows it.
2. **The history rewrite is not published (owner).** `main` on GitHub and
   sequoia continues the original history (the review and later commits sit
   on `342989a`), and the tags `v0.5.0`–`v0.6.2` are the original commits.
   The rewritten history prepared on 2026-09-11 (scratch clone at `da4432b`;
   the commands are in the owner's local notes) predates every commit since
   `342989a`, which must be replayed onto it before a force-push.
3. **A fresh clone does not build on its own (owner, with rump).** The
   manifest takes `rust-mp = { version = "0.3.0", path = "../rump" }`, and
   crates.io's newest `rust-mp` is 0.2.0, which lacks the APIs this crate
   uses (little-endian encoders, `mod_neg`, the FIPS 186-4 Lucas test). Until
   0.3 is published, building needs a checkout of
   [rump](https://github.com/darrelllong/rump) beside this one, as CI does;
   this crate cannot be published either. Once it is, depend on the registry
   version and keep the sibling path as a local override, and update the
   manifest gate in `src/scrub.rs` that requires the path.

## Documentation that is known stale

4. **Performance tables.** `ASYMMETRIC.md`, `SYMMETRIC.md` and `POSTQUANTUM.md`
   carry "Stale figures (2026-09-10)" notes. The instruments are corrected
   (MB = 10⁶ bytes, page-touch warm-up, fresh ML-DSA seeds, one agreement per
   timed span); re-sweep on quiet benchmark hosts, moving the tree to them by
   git, and regenerate the tables and radar plots with their units.

   State on 2026-09-17: pilot-bench's installed binaries no longer load —
   `libboost_log` 1.74 on darby, 1.83 on twilight, and a program-options
   symbol against Boost 1.92 on dyson — so each host needs it rebuilt from
   source before it can measure. Done on dyson (`~/pilot-bench/build-2026`);
   dennard's rebuild of 2026-09-05 runs. A sweep also needs the host quiet,
   which none of dyson, twilight or baase were: the three-platform set is
   dennard or twilight for x86-64, darby for aarch64 Linux, and dyson for
   Apple silicon, each taken when it is idle.

## Security contracts and evidence

5. **A message-encryption API.** Raw ElGamal (and the other raw schemes) are
   documented as primitives, not message encryption. If the crate is to
   offer message confidentiality, implement a complete published composition
   (for example RFC 9180 HPKE over a DH-KEM the crate already has) from its
   specification and vectors, with corrupted-encapsulation, AAD/context and
   invalid-key tests.
6. **Timing qualification beyond the primitives.** `scripts/ct_codegen.sh`
   classifies every conditional branch in the machine code of
   `Hmac::<Sha256>::verify`, `Aes128Ct::encrypt_block`, the X25519 and X448
   ladders, a complete X25519 key agreement and a complete ChaCha20-Poly1305
   open. On aarch64-apple-darwin (rustc 1.93.1) and
   x86_64-unknown-linux-gnu (rustc 1.95.0) each branch is a loop the source
   bounds, a guard on an index or an allocation, or a comparison of public
   lengths; `src/ct.rs`, `src/ciphers/aes.rs` and the two ladder modules
   record the reading, and CI fails the build when a claim gains a branch
   nobody has read. `scripts/ct_timing` adds the measured half: the dudect
   experiment with a positive control, whose runs are in its `RESULTS.md`.
   Still missing: complete signature operations, the remaining supported
   targets, and experiments over more input classes than fixed-against-random
   (low-order points, degenerate scalars, tag positions other than first and
   last).
7. **Targeted fuzzing.** Campaigns aimed at parser length and count fields,
    explicit domain parameters, key-pair consistency, nonce and counter
    exhaustion, authentication failure and failure-buffer contents, with the
   corpus, duration, features and revisions recorded.

8. **Named constants across the tree.** Every block cipher, stream cipher,
   hash, the DRBGs, the modes, the curve modules, HMAC, HKDF, RFC 6979,
   ML-KEM, ML-DSA, NTRU and the prime policy now name their widths, round
   counts, table sizes and bounds, and derive the ones that follow from
   another (AES's expanded key from `Nb(Nr + 1)`, SHA-3's rate from its
   capacity, Camellia's rounds from its six-round stages). What remains are
   byte offsets inside a word or a block, such as AES's four-byte column
   boundaries, where the literal reads better than a name.
9. **A specification-to-test map.** `SPECIFICATIONS.md` carries it: per
   algorithm, the document and section it is written from, where its known
   answers come from, and the tests that refuse malformed input, with
   conformance, interoperability and refusal kept apart. What it does not yet
   do is split a scheme's row per operation, so a reader cannot see which
   test covers signing as against verification.

## Statistical residuals to decide on

10. **Calibration covers one stream length.** The gap test's pooling depth
   depends on the stream length, so a battery run at any other `--bytes` needs
   its own calibration campaign.
