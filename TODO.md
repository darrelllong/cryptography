# TODO

The work queue after the full-tree review of 2026-09-15. Findings, rulings and
evidence are in `AUDIT.md`; this file lists only what is still to be done.
Items are marked **owner** when only the repository owner can do them.

## Publication and history

1. **Published releases carry the pre-audit code (owner).** The crates.io API
   on 2026-09-16 lists 0.5.0, 0.6.0, 0.6.1 and 0.6.2, none yanked; docs.rs
   serves the same sources. Yank them, and request deletion where crates.io
   policy allows it.
2. **The history rewrite is not published (owner).** `git ls-remote origin` on
   2026-09-16 shows `main` at `342989a` and the tags `v0.5.0`–`v0.6.2` at their
   original commits. The rewritten history prepared on 2026-09-11 (scratch
   clone at `da4432b`; commands in
   `~/cryptography-history-rewrite-2026-09-11/NOTES.md`) predates the review
   commit, which must be replayed onto it before a force-push.
3. **Push the review commit (owner).** It exists only locally. CI has never run
   on this tree; the first push is its first CI run (build, clippy on three
   feature sets, OpenSSL cross-checks with skipping forbidden, the entropy
   downstream job).

## Verification not yet repeated on this tree

4. **Release-only ignored tests on the fleet.** `cargo test --release --
   --ignored` last ran on dennard on 2026-09-10 (12 of 12). The tree now has
   15 ignored tests, including the `dm0` likelihood test and the FIPS 186-4
   DSA suites.
5. **Minimum supported Rust (1.87).** Not rebuilt since the review's changes.
6. **A real fuzz campaign.** Every one of the 45 targets has run, the new ones
   for a minute or more; that finds shallow crashes only. Run each target for
   hours on the fleet from the seed corpora, record iterations and coverage per
   target, and keep any minimized corpus growth.

## Documentation that is known stale

7. **Performance tables.** `ASYMMETRIC.md`, `SYMMETRIC.md` and `POSTQUANTUM.md`
   carry "Stale figures (2026-09-10)" notes. The instruments are corrected
   (MB = 10⁶ bytes, page-touch warm-up, fresh ML-DSA seeds, one agreement per
   timed span); re-sweep on dyson, dennard, moore and wigner, moving the tree to
   the fleet by git, and regenerate the tables and radar plots with their units.
8. **`SUGGESTIONS.md` predates the owner rulings.** Its items 1–6 are done, and
   several of its recommendations (opt-in wiping, a strict Ed25519 profile, an
   optional ML-KEM pair-wise test) were overruled. Retire it or rewrite it to
   hold only the feature and arithmetic directions below.

## Statistical residuals to decide on

9. **Gap test at the deciding threshold.** Over 400,000 null streams the gap
   test rejected 79 times at α/m against 57.1 expected (2.9 Poisson standard
   deviations high), while its rate at α = 10⁻³ is inside its interval. Its
   pooling depth was chosen at α; decide whether to re-derive it at α/m or to
   replace the χ² tail approximation with an exact or simulated null.
10. **Calibration covers one stream length.** The gap test's pooling depth
    depends on the stream length, so a battery run at any other `--bytes` needs
    its own calibration campaign.
11. **`ees443ep1` under the fixed test seeds.** The million-trial count sits two
    standard deviations above the exact refusal rate (the likelihood still
    favours the table's `dm0` by 57 nats). Rerun with independent seeds to see
    whether the offset persists.

## Directions (features and arithmetic, not defects)

12. **Constant-time curve arithmetic.** Fixed-width field arithmetic with
    branchless reduction for one named prime curve, then complete formulas and
    a fixed scalar schedule; the `vt` labels stay until the whole path is
    constant time.
13. **Folded GHASH.** The `Y_(i+b)` recurrence of SP 800-38D §6.4 with shared
    reduction, measured against the current 128-selection multiply.
14. **Standards not yet implemented.** SLH-DSA, Ed448 signatures, CTR_DRBG
    with a derivation function and prediction resistance, named finite-field
    groups (RFC 7919), and a specified ECIES KDF profile, each from its
    published specification with external vectors.
15. **Replay the ciphertext panel through entropy's battery**, recording corpus
    hashes, so the two batteries judge the same bytes.
