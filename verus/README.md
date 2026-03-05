# Verus Proof Scaffolding for `primes`

This directory holds standalone Verus proof artifacts for the `u128`-bounded
number-theory logic in `src/cprng/primes.rs`.

It is intentionally isolated from normal `cargo` builds.

## Scope (first slice)

`cprng_primes_u128.rs` currently focuses on the Miller-Rabin setup mechanics:

- Euclidean `gcd` loop: proved to match a recursive mathematical specification.
- Decomposition step: proved that `n - 1 = d * 2^s` with odd `d`.

These are foundational lemmas for later full proofs of:

- `mul_mod` correctness
- `mod_pow` correctness
- Miller-Rabin witness soundness for the fixed base set

## Running

Assuming Verus is installed and on `PATH`:

```bash
cd /Users/darrell/cryptography
verus verus/cprng_primes_u128.rs
```

If your Verus binary lives elsewhere:

```bash
cd /Users/darrell/cryptography
/path/to/verus verus/cprng_primes_u128.rs
```
