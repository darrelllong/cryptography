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

proof fn lemma_mod_add(x: nat, y: nat, m: nat)
    requires
        m > 0,
    ensures
        ((x % m) + (y % m)) % m == (x + y) % m
{
    assert(((x % m) + (y % m)) % m == (x + y) % m) by (nonlinear_arith);
}

proof fn lemma_mod_mul(x: nat, y: nat, m: nat)
    requires
        m > 0,
    ensures
        ((x % m) * (y % m)) % m == (x * y) % m
{
    assert(((x % m) * (y % m)) % m == (x * y) % m) by (nonlinear_arith);
}

spec fn mod_mul_spec(x: nat, y: nat, m: nat) -> nat
    recommends
        m > 0
{
    ((x % m) * (y % m)) % m
}

proof fn lemma_mod_mul_assoc(x: nat, y: nat, z: nat, m: nat)
    requires
        m > 0,
    ensures
        mod_mul_spec(mod_mul_spec(x, y, m), z, m) == mod_mul_spec(x, mod_mul_spec(y, z, m), m)
{
    assert(mod_mul_spec(mod_mul_spec(x, y, m), z, m) == mod_mul_spec(x, mod_mul_spec(y, z, m), m))
        by (nonlinear_arith);
}

proof fn lemma_mod_mul_one_left(x: nat, m: nat)
    requires
        m > 0,
    ensures
        mod_mul_spec(1, x, m) == x % m
{
    assert(mod_mul_spec(1, x, m) == x % m) by (nonlinear_arith);
}

spec fn mod_pow_sq_spec(base: nat, exp: nat, m: nat) -> nat
    recommends
        m > 0
    decreases exp
{
    if exp == 0 {
        1 % m
    } else {
        let sq = mod_mul_spec(base, base, m);
        let half = mod_pow_sq_spec(sq, exp / 2, m);
        if exp % 2 == 1 {
            mod_mul_spec(base, half, m)
        } else {
            half
        }
    }
}

// WHAT:
//   Bounded-u128 modular multiplication via double-and-add.
// WHY:
//   Mirrors src/cprng/primes.rs::mul_mod and proves the loop computes
//   (a mod m) * (b mod m) mod m under the same <2^127 bound assumption.
fn mul_mod_u128(a_input: u128, b_input: u128, m: u128) -> (out: u128)
    requires
        m > 0,
        m < (1u128 << 127),
    ensures
        out < m,
        out as nat == ((a_input as nat % m as nat) * (b_input as nat % m as nat)) % m as nat
{
    let m_nat = m as nat;
    let mut a = a_input % m;
    let mut b = b_input % m;
    let a0 = a;
    let b0 = b;
    let mut out = 0u128;

    while b != 0
        invariant
            m > 0,
            m < (1u128 << 127),
            a < m,
            b < m,
            out < m,
            (out as nat + (a as nat * b as nat)) % m_nat
                == ((a0 as nat * b0 as nat) % m_nat)
        decreases b
    {
        let a_prev = a;
        let b_prev = b;
        let out_prev = out;
        let q = b_prev / 2;
        let r = b_prev % 2;
        if r == 1 {
            out = (out_prev + a_prev) % m;
        }
        a = (a_prev << 1) % m;
        b = q;

        proof {
            lemma_mod_add(out_prev as nat, a_prev as nat, m_nat);
            lemma_mod_add(out_prev as nat, (a_prev as nat * b_prev as nat), m_nat);
            lemma_mod_mul((2 * a_prev as nat), q as nat, m_nat);
            lemma_mod_mul(a_prev as nat, b_prev as nat, m_nat);
            assert(b_prev as nat == 2 * q as nat + r as nat) by (nonlinear_arith);
            assert(r as nat == 0 || r as nat == 1) by (nonlinear_arith);
            assert((a_prev << 1) as nat == 2 * a_prev as nat) by (nonlinear_arith);
            assert(a_prev < (1u128 << 127));
            assert((out_prev as nat + (a_prev as nat * b_prev as nat)) % m_nat
                == ((a0 as nat * b0 as nat) % m_nat));

            if r == 1 {
                assert((out as nat + (a as nat * b as nat)) % m_nat
                    == (out_prev as nat + a_prev as nat + (2 * a_prev as nat) * q as nat) % m_nat) by (nonlinear_arith);
                assert((out_prev as nat + a_prev as nat + (2 * a_prev as nat) * q as nat) % m_nat
                    == (out_prev as nat + a_prev as nat * (2 * q as nat + 1)) % m_nat) by (nonlinear_arith);
                assert((2 * q as nat + 1) == b_prev as nat) by (nonlinear_arith);
            } else {
                assert(r == 0);
                assert((out as nat + (a as nat * b as nat)) % m_nat
                    == (out_prev as nat + (2 * a_prev as nat) * q as nat) % m_nat) by (nonlinear_arith);
                assert((out_prev as nat + (2 * a_prev as nat) * q as nat) % m_nat
                    == (out_prev as nat + a_prev as nat * (2 * q as nat)) % m_nat) by (nonlinear_arith);
                assert((2 * q as nat) == b_prev as nat) by (nonlinear_arith);
            }
        }
    }

    proof {
        assert((out as nat + (a as nat * b as nat)) % m_nat == ((a0 as nat * b0 as nat) % m_nat));
        assert(b == 0);
        assert((a as nat * b as nat) == 0) by (nonlinear_arith);
        assert(out as nat % m_nat == ((a0 as nat * b0 as nat) % m_nat));
        assert(out as nat == ((a0 as nat * b0 as nat) % m_nat));
    }
    out
}

// WHAT:
//   Bounded-u128 modular exponentiation by repeated squaring.
// WHY:
//   Mirrors src/cprng/primes.rs::mod_pow and proves the loop computes the
//   squaring-based modular exponentiation specification.
fn mod_pow_u128(base_input: u128, exp_input: u128, m: u128) -> (out: u128)
    requires
        m > 0,
        m < (1u128 << 127),
    ensures
        out < m,
        out as nat == mod_pow_sq_spec(base_input as nat % m as nat, exp_input as nat, m as nat)
{
    let m_nat = m as nat;
    let mut out = 1u128 % m;
    let mut power = base_input % m;
    let base0 = power;
    let exp0 = exp_input;
    let mut exp = exp_input;

    while exp != 0
        invariant
            m > 0,
            m < (1u128 << 127),
            out < m,
            power < m,
            mod_mul_spec(out as nat, mod_pow_sq_spec(power as nat, exp as nat, m_nat), m_nat)
                == mod_pow_sq_spec(base0 as nat, exp0 as nat, m_nat)
        decreases exp
    {
        let out_prev = out;
        let power_prev = power;
        let exp_prev = exp;
        let q = exp_prev / 2;
        let r = exp_prev % 2;
        if r == 1 {
            out = mul_mod_u128(out_prev, power_prev, m);
        }
        power = mul_mod_u128(power_prev, power_prev, m);
        exp = q;

        proof {
            assert(exp_prev as nat == 2 * q as nat + r as nat) by (nonlinear_arith);
            assert(r as nat == 0 || r as nat == 1) by (nonlinear_arith);

            if r == 1 {
                assert(exp_prev as nat % 2 == 1);
                assert(exp_prev as nat / 2 == q as nat);
                assert(mod_pow_sq_spec(power_prev as nat, exp_prev as nat, m_nat)
                    == mod_mul_spec(power_prev as nat, mod_pow_sq_spec(mod_mul_spec(power_prev as nat, power_prev as nat, m_nat), q as nat, m_nat), m_nat));

                assert(out as nat == mod_mul_spec(out_prev as nat, power_prev as nat, m_nat));
                lemma_mod_mul_assoc(out_prev as nat, power_prev as nat, mod_pow_sq_spec(mod_mul_spec(power_prev as nat, power_prev as nat, m_nat), q as nat, m_nat), m_nat);
                assert(mod_mul_spec(out as nat, mod_pow_sq_spec(power as nat, exp as nat, m_nat), m_nat)
                    == mod_mul_spec(out_prev as nat, mod_pow_sq_spec(power_prev as nat, exp_prev as nat, m_nat), m_nat));
            } else {
                assert(r == 0);
                assert(exp_prev as nat % 2 == 0);
                assert(exp_prev as nat / 2 == q as nat);
                assert(mod_pow_sq_spec(power_prev as nat, exp_prev as nat, m_nat)
                    == mod_pow_sq_spec(mod_mul_spec(power_prev as nat, power_prev as nat, m_nat), q as nat, m_nat));
                assert(out == out_prev);
                assert(mod_mul_spec(out as nat, mod_pow_sq_spec(power as nat, exp as nat, m_nat), m_nat)
                    == mod_mul_spec(out_prev as nat, mod_pow_sq_spec(power_prev as nat, exp_prev as nat, m_nat), m_nat));
            }
        }
    }

    proof {
        assert(exp == 0);
        assert(mod_pow_sq_spec(power as nat, exp as nat, m_nat) == 1 % m_nat);
        lemma_mod_mul_one_left(out as nat, m_nat);
        assert(mod_mul_spec(out as nat, mod_pow_sq_spec(power as nat, exp as nat, m_nat), m_nat) == out as nat);
        assert(out as nat == mod_pow_sq_spec(base0 as nat, exp0 as nat, m_nat));
    }
    out
}

// WHAT:
//   Deterministic precheck phase from src/cprng/primes.rs::is_probable_prime.
// WHY:
//   This stage is a complete, cheap filter: reject out-of-domain values and
//   numbers divisible by the fixed small-prime set, while accepting the small
//   primes themselves.
fn is_probable_prime_precheck_u128(n: u128) -> (ret: bool)
    ensures
        n < 2 ==> !ret,
        n >= (1u128 << 127) ==> !ret,

        n == 2 ==> ret,
        n == 3 ==> ret,
        n == 5 ==> ret,
        n == 7 ==> ret,
        n == 11 ==> ret,
        n == 13 ==> ret,
        n == 17 ==> ret,
        n == 19 ==> ret,
        n == 23 ==> ret,
        n == 29 ==> ret,
        n == 31 ==> ret,
        n == 37 ==> ret,

        (n != 2 && n % 2 == 0) ==> !ret,
        (n != 3 && n % 3 == 0) ==> !ret,
        (n != 5 && n % 5 == 0) ==> !ret,
        (n != 7 && n % 7 == 0) ==> !ret,
        (n != 11 && n % 11 == 0) ==> !ret,
        (n != 13 && n % 13 == 0) ==> !ret,
        (n != 17 && n % 17 == 0) ==> !ret,
        (n != 19 && n % 19 == 0) ==> !ret,
        (n != 23 && n % 23 == 0) ==> !ret,
        (n != 29 && n % 29 == 0) ==> !ret,
        (n != 31 && n % 31 == 0) ==> !ret,
        (n != 37 && n % 37 == 0) ==> !ret
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

proof fn smoke_mul_mod_examples()
{
    let x = mul_mod_u128(7, 13, 97);
    assert(x == 91);

    let y = mul_mod_u128(123456789, 987654321, 1_000_000_007);
    assert(y as nat == ((123456789nat % 1_000_000_007nat) * (987654321nat % 1_000_000_007nat)) % 1_000_000_007nat);
}

proof fn smoke_mod_pow_examples()
{
    let x = mod_pow_u128(7, 13, 97);
    assert(x == 38);

    let y = mod_pow_u128(5, 0, 97);
    assert(y == 1);
}

proof fn smoke_precheck_examples()
{
    assert(is_probable_prime_precheck_u128(0) == false);
    assert(is_probable_prime_precheck_u128(1) == false);
    assert(is_probable_prime_precheck_u128(2) == true);
    assert(is_probable_prime_precheck_u128(37) == true);
    assert(is_probable_prime_precheck_u128(39) == false);
    assert(is_probable_prime_precheck_u128(341) == false);
}

} // verus!
