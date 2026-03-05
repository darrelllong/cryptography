# Verus Proof Scaffolding for `primes`

This directory holds standalone Verus proof artifacts for the `u128`-bounded
number-theory logic in `src/cprng/primes.rs`.

It is intentionally isolated from normal `cargo` builds.

## Scope

`cprng_primes_u128.rs` now covers the full bounded-`u128` flow used in
`src/cprng/primes.rs`:

- Euclidean `gcd` loop: proved to match a recursive mathematical specification.
- Decomposition step: proved that `n - 1 = d * 2^s` with odd `d`.
- Bounded `mul_mod` loop: proved to compute
  `((a mod m) * (b mod m)) mod m` under `m < 2^127`.
- Bounded `mod_pow` loop: proved repeated-squaring correctness against a
  squaring-style recursive modular exponentiation spec.
- Primality precheck stage: proved behavior for domain guards and all fixed
  small-prime accept/reject branches used before Miller-Rabin rounds.
- Miller-Rabin witness pipeline:
  - one-base tail squaring/check recursion
  - one-base pass spec alignment
  - fixed-base conjunction (`3..37`)
- Full `is_probable_prime` mirror:
  precheck + decomposition + deterministic fixed-base Miller-Rabin.

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
