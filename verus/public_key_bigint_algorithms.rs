use vstd::prelude::*;
use vstd::arithmetic::div_mod::lemma_div_is_strictly_smaller;

verus! {

// WHAT:
//   Overflow-safe modular add branch used in the bounded-u128 model.
// WHY:
//   BigUint has unbounded limbs, but a bounded model needs branch-add to avoid
//   relying on wider machine arithmetic.
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
//   Step-accurate model for BigUint::mod_mul_plain's doubling loop.
// WHY:
//   This mirrors the fallback algorithm shape in src/public_key/bigint.rs.
spec fn mod_mul_plain_acc_spec(a: u128, b: u128, m: u128, out: u128) -> u128
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
        mod_mul_plain_acc_spec(a1, b / 2, m, out1)
    }
}

fn mod_mul_plain_acc_u128(a: u128, b: u128, m: u128, out: u128) -> (ret: u128)
    requires
        m > 0,
        m < (1u128 << 127),
        a < m,
        b < m,
        out < m,
    ensures
        ret < m,
        ret == mod_mul_plain_acc_spec(a, b, m, out)
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
        mod_mul_plain_acc_u128(a1, q, m, out1)
    }
}

// WHAT:
//   Bounded-u128 mirror of BigUint::mod_mul_plain.
// WHY:
//   Gives a verifier-checked executable model of the fallback multiplier path.
fn mod_mul_plain_u128(lhs: u128, rhs: u128, m: u128) -> (out: u128)
    requires
        m > 0,
        m < (1u128 << 127),
    ensures
        out < m,
        out == mod_mul_plain_acc_spec(lhs % m, rhs % m, m, 0)
{
    let a0 = lhs % m;
    let b0 = rhs % m;
    mod_mul_plain_acc_u128(a0, b0, m, 0)
}

// WHAT:
//   Exact Newton iteration from bigint.rs::montgomery_n0_inv.
// WHY:
//   This constant-time routine is central to Montgomery reduction setup.
spec fn montgomery_n0_inv_spec(n0: u64) -> u64
{
    let inv1 = 1u64;
    let inv2 = inv1.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv1)));
    let inv3 = inv2.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv2)));
    let inv4 = inv3.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv3)));
    let inv5 = inv4.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv4)));
    let inv6 = inv5.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv5)));
    let inv7 = inv6.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv6)));
    0u64.wrapping_sub(inv7)
}

fn montgomery_n0_inv_u64(n0: u64) -> (out: u64)
    requires
        n0 & 1 == 1,
    ensures
        out == montgomery_n0_inv_spec(n0)
{
    let inv1 = 1u64;
    let inv2 = inv1.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv1)));
    let inv3 = inv2.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv2)));
    let inv4 = inv3.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv3)));
    let inv5 = inv4.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv4)));
    let inv6 = inv5.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv5)));
    let inv7 = inv6.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv6)));
    let out = 0u64.wrapping_sub(inv7);
    out
}

proof fn smoke_montgomery_n0_inv_constants()
{
    assert(1u64.wrapping_mul(montgomery_n0_inv_spec(1)) == u64::MAX) by (compute);
    assert(3u64.wrapping_mul(montgomery_n0_inv_spec(3)) == u64::MAX) by (compute);
    assert(1_000_000_007u64.wrapping_mul(montgomery_n0_inv_spec(1_000_000_007u64)) == u64::MAX)
        by (compute);
}

} // verus!
