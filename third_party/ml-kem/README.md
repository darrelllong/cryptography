# ML-KEM Reference Intake

This directory tracks pinned upstream references used to implement ML-KEM
(Kyber) in pure Rust.

## Upstream sources

- NIST FIPS 203 (ML-KEM): `pubs/fips203-ml-kem.pdf`
- NIST SP 800-227 (KEM properties): `pubs/sp800-227-kem-properties.pdf`
- Reference source:
  - repository: `https://github.com/pq-crystals/kyber`
  - pinned commit: `4768bd37c02f9c40a46cb49d4d1f4d5e612bb882`
  - extracted path: `third_party/ml-kem/kyber-ref`

## Refresh workflow

Run:

```bash
bash scripts/fetch_mlkem_refs.sh
```

This refreshes the NIST PDFs and repopulates `kyber-ref` at the pinned commit.
