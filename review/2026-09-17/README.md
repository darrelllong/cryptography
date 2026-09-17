# Review evidence — 2026-09-17

`snapshots.json` identifies the frozen sibling revisions and reviewed-file
manifest digests. `reviewed-files.sha256` is the corresponding pre-review-artifact
manifest for this repository. `validation.json` records functional commands,
counts and log digests; the referenced logs are retained in `logs/`.

The source snapshots are the boundary of the test claims. Changes made in other
active tasks after capture are not silently included. Benchmark inputs and
measurements below keep their own identities and are not release qualification.

The functional release suites require OpenSSL and cover default and all features.
The shared ChaCha performance client and CSV are in
[entropy's evidence directory](../../../entropy/review/2026-09-17/README.md).
They test the initial captured ChaCha implementation through entropy's adapter;
they do not benchmark fast key erasure, TLS or reseeding.
