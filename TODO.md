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

   State on 2026-09-17: pilot-bench's installed binaries no longer loaded —
   `libboost_log` 1.74 on darby, 1.83 on twilight, a program-options symbol
   against Boost 1.92 on dyson — so it was rebuilt from source on dyson, darby
   and twilight (gcc needs `-Wno-error=unknown-pragmas` for the clang pragmas
   in `libpilot.cc`); baase's 2026-09-10 build and dennard's of 2026-09-05
   run as they are.

   Swept so far, at `d51efc3` with `PILOT_PRESET=normal` and a 90% CI: baase
   (Cortex-X925, idle) and darby (Raspberry Pi 5, idle) — symmetric and hash
   complete, public key running. Twilight's run was discarded when another
   user's job took the machine to load 118 partway through, and dyson is not
   quiet either. What is left is an x86-64 column on a quiet EPYC and the
   Apple-silicon column, then the merge, the radars and the table updates.

## Security contracts and evidence

5. **A message-encryption API.** Raw ElGamal (and the other raw schemes) are
   documented as primitives, not message encryption. If the crate is to
   offer message confidentiality, implement a complete published composition
   (for example RFC 9180 HPKE over a DH-KEM the crate already has) from its
   specification and vectors, with corrupted-encapsulation, AAD/context and
   invalid-key tests.
6. **Timing qualification beyond the primitives.** `scripts/ct_codegen.sh`
   classifies every conditional branch in the machine code of each claim the
   crate makes: the tag comparison, every `Ct` block cipher, the ChaCha20
   keystream, the Poly1305 MAC, the X25519 and X448 ladders, a complete
   X25519 key agreement, a complete ChaCha20-Poly1305 open, and the two
   constant-time KEM decapsulations (ML-KEM and NTRU round 3). On
   aarch64-apple-darwin and x86_64-unknown-linux-gnu every branch is a loop
   the source bounds, a guard that ends in a panic or the allocator, or a
   comparison of a public length, round count, encoding width or path
   selector; the claims table in the script says what each reading found,
   `scripts/ct_budgets/` holds the counts, and CI fails the build when a claim
   gains a branch nobody has read. `scripts/ct_timing` adds the measured half:
   the dudect experiment with both a positive and a negative control, over
   pairs of fixed inputs, whose runs are in its `RESULTS.md`.

   What the measurement found, and what is still open: on an Apple M4 Pro the
   ladder separates scalars by how often its conditional swap fires, for
   ordinary keys as well as degenerate ones (alternating bits against long
   runs, `|t|` 11 to 13), while an idle x86-64 host separates nothing and a
   Cortex-A76 separates only a low-order peer point. One countermeasure was
   tried and not kept: `RESULTS.md` records that it halved the statistic at an
   11% cost without removing it. What that asks for next is a countermeasure
   whose cost buys a statistic at the threshold — scalar blinding is the
   candidate, since it makes the swap pattern differ per call rather than per
   key — and runs of the whole battery on the remaining supported targets.
7. **Targeted fuzzing.** The 45 targets cover the parsers, the AEAD failure
   path — including, since this campaign, that a refused decryption leaves the
   caller's buffer as it found it — and every public-key surface;
   `scripts/fuzz_regressions.sh` replays the inputs behind repaired defects,
   and counter exhaustion is checked by tests, which can reach lengths a
   fuzzer cannot. Still to aim at: explicit domain parameters, key-pair
   consistency as its own target, and nonce reuse across calls. Campaign
   records, with corpus, duration, features and revisions, are in
   `fuzz/campaigns/`; the 2026-09-17 campaign ran all 45 targets for four
   hours each at 69d9fa6 with no crash and no regression input broken.

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
   conformance, interoperability and refusal kept apart, and each public-key
   row names the operations its known answers cover. What it does not yet do
   is name the individual test behind each of those operations, so a reader
   who wants the sigVer case specifically still has to open the file.

## Statistical residuals to decide on

10. **Calibration covers one stream length.** The gap test's pooling depth
   depends on the stream length, so a battery run at any other `--bytes` needs
   its own calibration campaign.
