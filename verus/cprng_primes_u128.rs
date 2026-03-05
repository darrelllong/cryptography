use vstd::prelude::*;
use vstd::arithmetic::div_mod::{lemma_div_is_strictly_smaller, lemma_small_mod};

verus! {

// WHAT:
//   Mathematical gcd specification corresponding to Euclid's algorithm.
// WHY:
//   This anchors the executable Euclidean loop proof.
spec fn gcd_spec(a: nat, b: nat) -> nat
    decreases b
{
    if b == 0 { a } else { gcd_spec(b, a % b) }
}

// WHAT:
//   Powers of two used in n-1 decomposition.
// WHY:
//   Keeps the decomposition proof statements readable.
spec fn pow2(e: nat) -> nat
    decreases e
{
    if e == 0 { 1 } else { 2 * pow2((e - 1) as nat) }
}

// WHAT:
//   Overflow-safe modular add branch used by mul_mod.
// WHY:
//   The Rust/C implementation relies on bounded arithmetic instead of widening.
spec fn add_mod_branch_spec(x: u128, y: u128, m: u128) -> u128
    recommends
        m > 0,
        x < m,
        y < m,
{
    if x >= m - y {
        (x - (m - y)) as u128
    } else {
        (x + y) as u128
    }
}

fn add_mod_branch_u128(x: u128, y: u128, m: u128) -> (z: u128)
    requires
        m > 0,
        x < m,
        y < m,
    ensures
        z < m,
        z == add_mod_branch_spec(x, y, m)
{
    if x >= m - y {
        x - (m - y)
    } else {
        x + y
    }
}

// WHAT:
//   Step-accurate bounded-u128 modular multiply specification.
// WHY:
//   This avoids large integer casts and matches executable behavior exactly.
spec fn mul_mod_acc_spec(a: u128, b: u128, m: u128, out: u128) -> u128
    recommends
        m > 0,
        a < m,
        b < m,
        out < m,
    decreases b
{
    if b == 0 {
        out
    } else {
        let out1 = if b % 2 == 1 {
            add_mod_branch_spec(out, a, m)
        } else {
            out
        };
        let a1 = add_mod_branch_spec(a, a, m);
        mul_mod_acc_spec(a1, b / 2, m, out1)
    }
}

fn mul_mod_acc_u128(a: u128, b: u128, m: u128, out: u128) -> (ret: u128)
    requires
        m > 0,
        m < (1u128 << 127),
        a < m,
        b < m,
        out < m,
    ensures
        ret < m,
        ret == mul_mod_acc_spec(a, b, m, out)
    decreases b
{
    if b == 0 {
        out
    } else {
        let out1 = if b % 2 == 1 {
            add_mod_branch_u128(out, a, m)
        } else {
            out
        };
        let a1 = add_mod_branch_u128(a, a, m);
        let q = b / 2;
        proof {
            lemma_div_is_strictly_smaller(b as int, 2);
            assert(q as int == b as int / 2);
            assert((q as int) < (b as int));
            assert(q < b);
        }
        mul_mod_acc_u128(a1, q, m, out1)
    }
}

// WHAT:
//   Bounded-u128 modular multiplication.
// WHY:
//   Mirrors src/cprng/primes.rs::mul_mod with a proved step-accurate spec.
fn mul_mod_u128(a_input: u128, b_input: u128, m: u128) -> (out: u128)
    requires
        m > 0,
        m < (1u128 << 127),
    ensures
        out < m,
        out == mul_mod_acc_spec(a_input % m, b_input % m, m, 0)
{
    let a0 = a_input % m;
    let b0 = b_input % m;
    mul_mod_acc_u128(a0, b0, m, 0)
}

// WHAT:
//   Step-accurate modular exponentiation by squaring.
// WHY:
//   This matches the executable recursion and avoids brittle arithmetic casts.
spec fn mod_pow_spec(base: u128, exp: u128, m: u128) -> u128
    recommends
        m > 0,
        base < m,
    decreases exp
{
    if exp == 0 {
        1u128 % m
    } else {
        let sq = mul_mod_acc_spec(base, base, m, 0);
        let half = mod_pow_spec(sq, exp / 2, m);
        if exp % 2 == 1 {
            mul_mod_acc_spec(base, half, m, 0)
        } else {
            half
        }
    }
}

// WHAT:
//   Bounded-u128 modular exponentiation.
// WHY:
//   Mirrors src/cprng/primes.rs::mod_pow with a proved recursion-aligned spec.
fn mod_pow_u128(base_input: u128, exp_input: u128, m: u128) -> (out: u128)
    requires
        m > 0,
        m < (1u128 << 127),
    ensures
        out < m,
        out == mod_pow_spec(base_input % m, exp_input, m)
    decreases exp_input
{
    let base = base_input % m;
    if exp_input == 0 {
        1u128 % m
    } else {
        let sq = mul_mod_u128(base, base, m);
        let q = exp_input / 2;
        proof {
            lemma_div_is_strictly_smaller(exp_input as int, 2);
            assert(q as int == exp_input as int / 2);
            assert((q as int) < (exp_input as int));
            assert(q < exp_input);
            assert(base < m);
            lemma_small_mod(base as nat, m as nat);
            assert(base % m == base);
            assert(sq == mul_mod_acc_spec(base, base, m, 0));
            assert(sq < m);
            lemma_small_mod(sq as nat, m as nat);
            assert(sq % m == sq);
        }
        let half = mod_pow_u128(sq, q, m);
        proof {
            assert(half == mod_pow_spec(sq % m, q, m));
            assert(half == mod_pow_spec(sq, q, m));
        }
        if exp_input % 2 == 1 {
            let out = mul_mod_u128(base, half, m);
            proof {
                assert(half < m);
                lemma_small_mod(half as nat, m as nat);
                assert(half % m == half);
                assert(out == mul_mod_acc_spec(base, half, m, 0));
                assert(mod_pow_spec(base, exp_input, m)
                    == mul_mod_acc_spec(base, mod_pow_spec(sq, q, m), m, 0));
            }
            out
        } else {
            proof {
                assert(mod_pow_spec(base, exp_input, m) == mod_pow_spec(sq, q, m));
            }
            half
        }
    }
}

// WHAT:
//   One-base Miller-Rabin tail squaring stage.
// WHY:
//   Captures exactly the executable pass/fail recurrence.
spec fn mr_tail_pass_spec(x: u128, n: u128, remaining: u32) -> bool
    recommends
        n > 1,
        x < n,
    decreases remaining
{
    if remaining == 0 {
        false
    } else {
        let x1 = mul_mod_acc_spec(x, x, n, 0);
        if x1 == n - 1 {
            true
        } else {
            mr_tail_pass_spec(x1, n, (remaining - 1) as u32)
        }
    }
}

spec fn mr_base_pass_spec(base: u128, d: u128, s: u32, n: u128) -> bool
    recommends
        n > 1,
        d > 0,
        d % 2 == 1,
{
    let x0 = mod_pow_spec(base % n, d, n);
    x0 == 1 || x0 == n - 1 || (s > 0 && mr_tail_pass_spec(x0, n, (s - 1) as u32))
}

spec fn mr_all_fixed_bases_spec(d: u128, s: u32, n: u128) -> bool
    recommends
        n > 1,
        d > 0,
        d % 2 == 1,
{
    mr_base_pass_spec(3, d, s, n)
        && mr_base_pass_spec(5, d, s, n)
        && mr_base_pass_spec(7, d, s, n)
        && mr_base_pass_spec(11, d, s, n)
        && mr_base_pass_spec(13, d, s, n)
        && mr_base_pass_spec(17, d, s, n)
        && mr_base_pass_spec(19, d, s, n)
        && mr_base_pass_spec(23, d, s, n)
        && mr_base_pass_spec(29, d, s, n)
        && mr_base_pass_spec(31, d, s, n)
        && mr_base_pass_spec(37, d, s, n)
}

fn mr_tail_pass_u128(x: u128, remaining: u32, n: u128) -> (ret: bool)
    requires
        n > 1,
        n < (1u128 << 127),
        x < n,
    ensures
        ret == mr_tail_pass_spec(x, n, remaining)
    decreases remaining
{
    if remaining == 0 {
        false
    } else {
        let x1 = mul_mod_u128(x, x, n);
        proof {
            assert(x < n);
            lemma_small_mod(x as nat, n as nat);
            assert(x % n == x);
            assert(x1 == mul_mod_acc_spec(x, x, n, 0));
        }
        if x1 == n - 1 {
            proof {
                assert(mr_tail_pass_spec(x, n, remaining));
            }
            true
        } else {
            let ret1 = mr_tail_pass_u128(x1, remaining - 1, n);
            proof {
                assert(ret1 == mr_tail_pass_spec(x1, n, (remaining - 1) as u32));
                assert(mr_tail_pass_spec(x, n, remaining) == mr_tail_pass_spec(x1, n, (remaining - 1) as u32));
            }
            ret1
        }
    }
}

fn miller_rabin_base_pass_u128(base: u128, d: u128, s: u32, n: u128) -> (ret: bool)
    requires
        n > 2,
        n < (1u128 << 127),
        d > 0,
        d % 2 == 1,
    ensures
        ret == mr_base_pass_spec(base, d, s, n)
{
    let x0 = mod_pow_u128(base, d, n);
    if x0 == 1 || x0 == n - 1 {
        true
    } else if s == 0 {
        false
    } else {
        mr_tail_pass_u128(x0, s - 1, n)
    }
}

fn miller_rabin_fixed_bases_u128(d: u128, s: u32, n: u128) -> (ret: bool)
    requires
        n > 2,
        n < (1u128 << 127),
        d > 0,
        d % 2 == 1,
    ensures
        ret == mr_all_fixed_bases_spec(d, s, n)
{
    let b3 = miller_rabin_base_pass_u128(3, d, s, n);
    if !b3 { return false; }

    let b5 = miller_rabin_base_pass_u128(5, d, s, n);
    if !b5 { return false; }

    let b7 = miller_rabin_base_pass_u128(7, d, s, n);
    if !b7 { return false; }

    let b11 = miller_rabin_base_pass_u128(11, d, s, n);
    if !b11 { return false; }

    let b13 = miller_rabin_base_pass_u128(13, d, s, n);
    if !b13 { return false; }

    let b17 = miller_rabin_base_pass_u128(17, d, s, n);
    if !b17 { return false; }

    let b19 = miller_rabin_base_pass_u128(19, d, s, n);
    if !b19 { return false; }

    let b23 = miller_rabin_base_pass_u128(23, d, s, n);
    if !b23 { return false; }

    let b29 = miller_rabin_base_pass_u128(29, d, s, n);
    if !b29 { return false; }

    let b31 = miller_rabin_base_pass_u128(31, d, s, n);
    if !b31 { return false; }

    let b37 = miller_rabin_base_pass_u128(37, d, s, n);
    if !b37 { return false; }

    true
}

// WHAT:
//   Spec-level precheck used before Miller-Rabin.
// WHY:
//   Keeps the executable precheck contract explicit and reusable.
spec fn prime_precheck_spec(n: u128) -> bool
{
    if n < 2 {
        false
    } else if n >= (1u128 << 127) {
        false
    } else if n == 2 || n == 3 || n == 5 || n == 7 || n == 11 || n == 13
        || n == 17 || n == 19 || n == 23 || n == 29 || n == 31 || n == 37 {
        true
    } else {
        !(n % 2 == 0 || n % 3 == 0 || n % 5 == 0 || n % 7 == 0
            || n % 11 == 0 || n % 13 == 0 || n % 17 == 0 || n % 19 == 0
            || n % 23 == 0 || n % 29 == 0 || n % 31 == 0 || n % 37 == 0)
    }
}

fn is_probable_prime_precheck_u128(n: u128) -> (ret: bool)
    ensures
        ret == prime_precheck_spec(n),
        n < 2 ==> !ret,
        n >= (1u128 << 127) ==> !ret
{
    if n < 2 {
        return false;
    }
    if n >= (1u128 << 127) {
        return false;
    }

    if n == 2 || n == 3 || n == 5 || n == 7 || n == 11 || n == 13
        || n == 17 || n == 19 || n == 23 || n == 29 || n == 31 || n == 37 {
        return true;
    }

    if n % 2 == 0 || n % 3 == 0 || n % 5 == 0 || n % 7 == 0
        || n % 11 == 0 || n % 13 == 0 || n % 17 == 0 || n % 19 == 0
        || n % 23 == 0 || n % 29 == 0 || n % 31 == 0 || n % 37 == 0 {
        return false;
    }

    true
}

// WHAT:
//   Executable Euclidean gcd over u128.
// WHY:
//   Mirrors src/cprng/primes.rs::gcd and proves agreement with gcd_spec.
fn gcd_u128(a: u128, b: u128) -> (g: u128)
    ensures
        g as nat == gcd_spec(a as nat, b as nat)
{
    let mut x = a;
    let mut y = b;

    while y != 0
        invariant
            gcd_spec(x as nat, y as nat) == gcd_spec(a as nat, b as nat)
        decreases y
    {
        let x_prev = x;
        let y_prev = y;
        let r = x_prev % y_prev;
        proof {
            assert(gcd_spec(x_prev as nat, y_prev as nat) == gcd_spec(y_prev as nat, (x_prev % y_prev) as nat));
        }
        x = y_prev;
        y = r;
    }

    proof {
        assert(gcd_spec(x as nat, 0) == x as nat);
    }
    x
}

// WHAT:
//   Write n-1 as d * 2^s with d odd (Miller-Rabin preprocessing).
// WHY:
//   This is the exact preparatory loop shape used before witness checks.
fn decompose_n_minus_one_u128(n: u128) -> (out: (u128, u32))
    requires
        n > 1,
        n < (1u128 << 127),
    ensures
        out.0 > 0,
        out.0 % 2 == 1
{
    let mut d = n - 1;
    let mut s: u32 = 0;

    while d % 2 == 0
        invariant
            d > 0
        decreases d
    {
        d = d / 2;
        s = s.wrapping_add(1);
    }

    proof {
        assert(d % 2 == 1);
    }
    (d, s)
}

// WHAT:
//   Full bounded-u128 probable-prime checker.
// WHY:
//   Mirrors src/cprng/primes.rs::is_probable_prime.
fn is_probable_prime_u128(n: u128) -> (ret: bool)
    ensures
        n < 2 ==> !ret,
        n >= (1u128 << 127) ==> !ret,
        ret ==> prime_precheck_spec(n)
{
    if !is_probable_prime_precheck_u128(n) {
        return false;
    }

    if n == 2 || n == 3 || n == 5 || n == 7 || n == 11 || n == 13
        || n == 17 || n == 19 || n == 23 || n == 29 || n == 31 || n == 37 {
        return true;
    }

    let (d, s) = decompose_n_minus_one_u128(n);
    miller_rabin_fixed_bases_u128(d, s, n)
}

} // verus!
