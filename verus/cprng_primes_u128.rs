use vstd::prelude::*;

verus! {

// WHAT:
//   Mathematical gcd specification corresponding to Euclid's algorithm.
// WHY:
//   This is the core loop invariant anchor for proving executable gcd code.
spec fn gcd_spec(a: nat, b: nat) -> nat
    decreases b
{
    if b == 0 { a } else { gcd_spec(b, a % b) }
}

// WHAT:
//   Powers of two used by the Miller-Rabin decomposition n-1 = d * 2^s.
// WHY:
//   This lets us state and prove the decompose loop postcondition directly.
spec fn pow2(e: nat) -> nat
    decreases e
{
    if e == 0 { 1 } else { 2 * pow2((e - 1) as nat) }
}

proof fn lemma_pow2_succ(k: nat)
    ensures
        pow2(k + 1) == 2 * pow2(k)
{
}

proof fn lemma_even_div2_mul2(x: nat)
    requires
        x % 2 == 0,
    ensures
        (x / 2) * 2 == x
{
    assert(x == (x / 2) * 2 + (x % 2)) by (nonlinear_arith);
}

// WHAT:
//   Executable Euclidean gcd over u128.
// WHY:
//   Mirrors src/cprng/primes.rs::gcd and proves the loop computes gcd_spec.
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
//   This is the exact preparatory loop used in src/cprng/primes.rs before
//   witness checks.
fn decompose_n_minus_one_u128(n: u128) -> (d: u128, s: u32)
    requires
        n > 1,
    ensures
        d > 0,
        d % 2 == 1,
        (n as nat - 1) == d as nat * pow2(s as nat)
{
    let mut d = n - 1;
    let mut s: u32 = 0;

    while d % 2 == 0
        invariant
            d > 0,
            (n as nat - 1) == d as nat * pow2(s as nat)
        decreases d
    {
        let d_prev = d;
        let s_prev = s;
        d = d_prev / 2;
        s = s_prev + 1;

        proof {
            lemma_pow2_succ(s_prev as nat);
            lemma_even_div2_mul2(d_prev as nat);
            assert(d_prev % 2 == 0);
            assert((d_prev as nat / 2) == d as nat);
            assert((n as nat - 1) == d_prev as nat * pow2(s_prev as nat));
            assert((n as nat - 1) == d as nat * pow2(s as nat));
        }
    }

    proof {
        assert(d % 2 == 1);
    }
    (d, s)
}

proof fn smoke_gcd_examples()
{
    let g1 = gcd_u128(18, 12);
    assert(g1 == 6);

    let g2 = gcd_u128(17, 13);
    assert(g2 == 1);
}

proof fn smoke_decompose_examples()
{
    let (d1, s1) = decompose_n_minus_one_u128(97);
    assert(d1 % 2 == 1);
    assert((97nat - 1) == d1 as nat * pow2(s1 as nat));

    let (d2, s2) = decompose_n_minus_one_u128(65);
    assert(d2 % 2 == 1);
    assert((65nat - 1) == d2 as nat * pow2(s2 as nat));
}

} // verus!
