use vstd::prelude::*;
use vstd::arithmetic::div_mod::lemma_mod_bound;

verus! {

// WHAT:
//   Checked add primitive used by limb-level accumulation.
// WHY:
//   BigUint add carries rely on exact machine-word sums.
fn add_u128_checked(a: u128, b: u128) -> (out: u128)
    requires
        a <= u128::MAX - b,
    ensures
        out == a + b,
{
    a + b
}

// WHAT:
//   Checked subtract primitive used by limb-level borrow logic.
// WHY:
//   BigUint subtraction assumes no underflow in the selected branch.
fn sub_u128_checked(a: u128, b: u128) -> (out: u128)
    requires
        a >= b,
    ensures
        out == a - b,
{
    a - b
}

// WHAT:
//   Checked multiply primitive for bounded modeling.
// WHY:
//   Schoolbook limb products reduce to bounded primitive multiplies.
fn mul_u128_checked(a: u128, b: u128) -> (out: u128)
    requires
        (a as int) * (b as int) <= u128::MAX as int,
    ensures
        out == a * b,
{
    a * b
}

// WHAT:
//   Read one bit from a u128 value.
// WHY:
//   Mirrors BigUint::bit behavior in a bounded model.
fn bit_u128(x: u128, index: u32) -> (out: bool)
    requires
        index < 128,
    ensures
        out == ((((x >> index) & 1u128) == 1u128)),
{
    ((x >> index) & 1u128) == 1u128
}

// WHAT:
//   Set one bit in a u128 value.
// WHY:
//   Mirrors BigUint::set_bit semantics in a bounded model.
fn set_bit_u128(x: u128, index: u32) -> (out: u128)
    requires
        index < 128,
    ensures
        out == (x | (1u128 << index)),
{
    x | (1u128 << index)
}

// WHAT:
//   Shift-left by one bit.
// WHY:
//   BigUint::shl1 is the fundamental doubling primitive in multiple algorithms.
fn shl1_u128(x: u128) -> (out: u128)
    ensures
        out == (x << 1u32),
{
    x << 1u32
}

// WHAT:
//   Shift-right by one bit.
// WHY:
//   BigUint::shr1 drives division and modular multiplication scans.
fn shr1_u128(x: u128) -> (out: u128)
    ensures
        out == (x >> 1u32),
{
    x >> 1u32
}

// WHAT:
//   Left-shift by n bits through repeated single-bit shifts.
// WHY:
//   Matches the conceptual structure of shift loops in bigint code.
fn shl_bits_u128(x: u128, n: u32) -> (out: u128)
    requires
        n < 128,
    ensures
        out == (x << n),
{
    let mut acc = x;
    let mut i: u32 = 0;
    proof {
        assert(i == 0u32);
        assert(acc == x);
        assert((x << 0u32) == x) by (bit_vector);
        assert(acc == (x << i));
    }
    while i < n
        invariant
            i <= n,
            acc == (x << i),
        decreases n - i
    {
        let i_prev = i;
        let acc_prev = acc;
        acc = acc << 1u32;
        i = i + 1;
        proof {
            assert(i == i_prev + 1);
            assert(acc == (acc_prev << 1u32));
            assert((x << i_prev) << 1u32 == (x << (i_prev + 1))) by (bit_vector);
            assert(acc == (x << i));
        }
    }
    acc
}

// WHAT:
//   Plain modulo with non-zero modulus.
// WHY:
//   BigUint::rem_u64 and modulo paths reduce to this arithmetic relation.
fn rem_u128(x: u128, m: u128) -> (out: u128)
    requires
        m > 0,
    ensures
        out == x % m,
        out < m,
{
    let out = x % m;
    proof {
        lemma_mod_bound(x as int, m as int);
        assert(0 <= (out as int));
        assert((out as int) < (m as int));
        assert(out < m);
    }
    out
}

} // verus!
