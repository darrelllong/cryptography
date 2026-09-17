# TODO

The work queue. The outside review's findings are in `AUDIT.md` and its
proposals in `SUGGESTIONS.md`; this file lists only what is still to be done.
Items are marked **owner** when only the repository owner can do them.

## Publication and history

1. **Published releases carry the pre-audit code (owner).** The crates.io API
   on 2026-09-16 lists 0.5.0, 0.6.0, 0.6.1 and 0.6.2, none yanked; docs.rs
   serves the same sources. Yank them, and request deletion where crates.io
   policy allows it.
2. **The history rewrite is not published (owner).** `git ls-remote origin` on
   2026-09-16 shows `main` at `342989a` and the tags `v0.5.0`–`v0.6.2` at their
   original commits. The rewritten history prepared on 2026-09-11 (scratch
   clone at `da4432b`; the commands are in the owner's local notes) predates
   the review commit, which must be replayed onto it before a force-push.
3. **Push the review commit (owner).** It exists only locally. CI has never run
   on this tree; the first push is its first CI run. The test suites pass on
   Linux x86-64 against OpenSSL 3.0.13, the release the Ubuntu runners
   carry, with rump `70d1283`.
4. **A fresh clone does not build on its own (owner, with rump).** The
   manifest takes `rust-mp = { version = "0.3.0", path = "../rump" }`, and
   crates.io's newest `rust-mp` is 0.2.0, which lacks the APIs this crate
   uses (little-endian encoders, `mod_neg`, the FIPS 186-4 Lucas test). Until
   0.3 is published, building needs a checkout of
   [rump](https://github.com/darrelllong/rump) beside this one, as CI does;
   this crate cannot be published either. Once it is, depend on the registry
   version and keep the sibling path as a local override, and update the
   manifest gate in `src/scrub.rs` that requires the path.

## Documentation that is known stale

5. **Performance tables.** `ASYMMETRIC.md`, `SYMMETRIC.md` and `POSTQUANTUM.md`
   carry "Stale figures (2026-09-10)" notes. The instruments are corrected
   (MB = 10⁶ bytes, page-touch warm-up, fresh ML-DSA seeds, one agreement per
   timed span); re-sweep on quiet benchmark hosts, moving the tree to them by
   git, and regenerate the tables and radar plots with their units.

## Statistical residuals to decide on

6. **Gap test at the deciding threshold.** Over 400,000 null streams the gap
   test rejected 79 times at α/m against 57.1 expected (2.9 Poisson standard
   deviations high), while its rate at α = 10⁻³ is inside its interval. Its
   pooling depth was chosen at α; decide whether to re-derive it at α/m or to
   replace the χ² tail approximation with an exact or simulated null.
7. **Calibration covers one stream length.** The gap test's pooling depth
   depends on the stream length, so a battery run at any other `--bytes` needs
   its own calibration campaign.
