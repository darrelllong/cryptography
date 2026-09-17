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

## Security contracts and evidence

5. **A message-encryption API.** Raw ElGamal (and the other raw schemes) are
   documented as primitives, not message encryption. If the crate is to
   offer message confidentiality, implement a complete published composition
   (for example RFC 9180 HPKE over a DH-KEM the crate already has) from its
   specification and vectors, with corrupted-encapsulation, AAD/context and
   invalid-key tests.
6. **Timing qualification beyond the tag comparison.** `scripts/ct_codegen.sh`
   now reads the machine code of `Hmac::<Sha256>::verify` and finds only
   public-length branches on aarch64-apple-darwin and x86_64-unknown-linux-gnu.
   The `Ct` ciphers, the X25519/X448 ladders and complete AEAD, signature and
   key-agreement operations have no such evidence: extend the probe to them,
   run it on every supported target, and add predeclared interleaved
   input-class timing experiments with reported distributions.
7. **Targeted fuzzing.** Campaigns aimed at parser length and count fields,
    explicit domain parameters, key-pair consistency, nonce and counter
    exhaustion, authentication failure and failure-buffer contents, with the
   corpus, duration, features and revisions recorded.

8. **Named constants across the tree.** Today's generator, ChaCha20, NTRU and
   benchmark constants carry their derivations. The rest of the tree still
   holds bare literals for spec-fixed widths, round counts and table sizes;
   sweep each module and name them or cite the section that fixes them.
9. **A specification-to-test map.** For each scheme, a table from
    specification version and section to the operation, its accepted inputs
    and the test that checks it, separating valid-vector conformance from
    refusal of malformed input.

## Statistical residuals to decide on

10. **Calibration covers one stream length.** The gap test's pooling depth
   depends on the stream length, so a battery run at any other `--bytes` needs
   its own calibration campaign.
