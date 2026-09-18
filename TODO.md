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

4. **Performance tables (done, with one gap).** `SYMMETRIC.md`,
   `ASYMMETRIC.md` and `POSTQUANTUM.md` carry the 2026-09-17 sweep: four
   columns — Intel i5-8259U (`dmz`), Apple M1 (`tolkien`), Cortex-X925
   (`baase`) and Cortex-A76 (`darby`) — merged, with every radar redrawn and
   every ratio in the surrounding prose recomputed. The staleness notes are
   gone where the numbers are now current, and narrowed where they are not:
   `SYMMETRIC.md`'s go-fast comparison sections remain older single-host
   snapshots whose GHASH baseline is the comparator the SP 800-38D multiply
   replaced.

   The gap is the x86-64 column: it is a mobile part, because both EPYC hosts
   carried other users' work throughout. `twilight`'s attempt was discarded
   when another user's job took it to load 118 partway through. An EPYC column
   would be worth adding when one of those machines is genuinely free.

   The three sweep scripts took exactly three platforms until this round;
   they take any number now, which is what let a fourth host in.

## Security contracts and evidence

5. **A message-encryption API.** RFC 9180 HPKE over
   `DHKEM(X25519, HKDF-SHA256)` is implemented in `src/public_key/hpke.rs`,
   in all four modes and with three AEADs, and checked against the whole of
   the RFC's Appendix A.1 and A.2 along with the refusals a composition owes:
   a changed encapsulation, info string, associated data or ciphertext, a
   low-order encapsulation, and the wrong key on either side. What is not
   here is the rest of §7: the P-256 and P-521 KEMs, HKDF-SHA384 and
   HKDF-SHA512, and the export-only AEAD.
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
   11% cost without removing it. Scalar blinding, the candidate that would make
   the swap pattern differ per call rather than per key, is priced in
   `RESULTS.md` and not taken: the modulus that leaves every input unchanged —
   including the twist points RFC 7748 accepts — is `lcm(8l, 4l') = 8ll'` at
   508 bits, so the ladder would take 2.24 times as long, and the cheaper
   1.25-fold blinding by the curve order alone changes the result for twist
   inputs and is therefore not X25519. What is left is the whole battery on
   the remaining supported targets; four hosts are in `RESULTS.md`.
7. **Targeted fuzzing.** The 49 targets cover the parsers, the AEAD failure
   path — including, since this campaign, that a refused decryption leaves the
   caller's buffer as it found it — and every public-key surface;
   `scripts/fuzz_regressions.sh` replays the inputs behind repaired defects,
   and counter exhaustion is checked by tests, which can reach lengths a
   fuzzer cannot. Explicit domain parameters are now their own target,
   `fuzz_explicit_curve`, which perturbs one field of a named curve at a time
   so the deep checks are reached, and key-pair consistency is
   `fuzz_key_pair`, which crosses two generated pairs in five schemes and
   splices an ML-KEM decapsulation key so only FIPS 203's pair-wise test can
   refuse it. Counter reuse across calls is `fuzz_counter_reuse`, which
   requires a chunked encryption to equal a single call, an advanced counter
   to equal a later start, and the remaining-keystream count to fall by what
   was taken. Campaign
   records, with corpus, duration, features and revisions, are in
   `fuzz/campaigns/`; the 2026-09-17 campaign ran all 45 targets then defined
   for four hours each at 69d9fa6 with no crash and no regression input
   broken. The four targets written after it — HPKE, explicit curve
   parameters, key-pair consistency and counter reuse — have had an hour each
   on a busy machine with no crash, recorded in
   `fuzz/campaigns/2026-09-17-new-targets.txt`; they belong in the next full
   campaign on quiet hosts.

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
   conformance, interoperability and refusal kept apart, each public-key row
   naming the operations its known answers cover, and a table under it naming
   the test behind each of those operations — 106 of them, each checked to
   exist. Building that table found three rows claiming more than the tree
   holds, which are corrected, and one operation with no test, which now has
   one.

10. **RSA PKCS #1 v1.5 is not implemented (owner's call).** `SPECIFICATIONS.md`
   claimed it until the map above was built; the crate has RSAES-OAEP and
   RSASSA-PSS and nothing for §7.2 or §8.2. Verifying v1.5 signatures is what
   interoperating with older systems asks for, and the padding's decryption
   side is the one Bleichenbacher broke. Whether to add verification only, add
   both behind a name that says what they are, or state the omission as
   policy, is a decision rather than an oversight to fix.

## Statistical residuals to decide on

11. **Calibration covers one stream length.** The gap test's pooling depth
   depends on the stream length, so a battery run at any other `--bytes` needs
   its own calibration campaign.
