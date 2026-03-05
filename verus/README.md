# Verus Proof Scaffolding for `primes`

This directory holds standalone Verus proof artifacts for the `u128`-bounded
number-theory logic in `src/cprng/primes.rs`.

It is intentionally isolated from normal `cargo` builds.

## Scope

`cprng_primes_u128.rs` now covers the full bounded-`u128` flow used in
`src/cprng/primes.rs`:

- Euclidean `gcd` loop: proved to match a recursive mathematical specification.
- Decomposition step: proved odd/positive `d` output from the halving loop.
- Bounded `mul_mod` loop: proved against a step-accurate recursive `u128`
  spec that mirrors the overflow-safe branch updates.
- Bounded `mod_pow` loop: proved against a repeated-squaring recursive `u128`
  spec built on the proved `mul_mod` spec.
- Primality precheck stage: proved behavior for domain guards and all fixed
  small-prime accept/reject branches used before Miller-Rabin rounds.
- Miller-Rabin witness pipeline:
  - one-base tail squaring/check recursion
  - one-base pass spec alignment
  - fixed-base conjunction (`3..37`)
- Full `is_probable_prime` mirror:
  precheck + decomposition + deterministic fixed-base Miller-Rabin.

`public_key_bigint_algorithms.rs` provides a first proof slice for
`src/public_key/bigint.rs`:

- Bounded-`u128` executable mirror of the `mod_mul_plain` fallback loop with a
  step-accurate recursive specification.
- Executable mirror of the `montgomery_n0_inv` Newton iteration with an exact
  spec-level correspondence proof.
- Constant examples showing the Newton-derived value satisfies
  `n0 * n0_inv == -1 (mod 2^64)` for representative odd moduli.

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
