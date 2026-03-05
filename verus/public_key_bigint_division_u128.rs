use vstd::prelude::*;

verus! {

// WHAT:
//   Extract the next bit for an MSB-first division pass.
// WHY:
//   BigUint::div_rem consumes dividend bits from high to low.
spec fn msb_step_bit(x: u128, len: nat) -> u128
    recommends
        1 <= len <= 128,
{
    (x >> ((128 - len) as u32)) & 1u128
}

// WHAT:
//   Recursive model of high-bit prefix construction.
// WHY:
//   The long-division recurrence updates quotient/remainder from this prefix.
spec fn prefix_len_spec(x: u128, len: nat) -> u128
    recommends
        len <= 128,
    decreases len
{
    if len == 0 {
        0u128
    } else {
        (prefix_len_spec(x, (len - 1) as nat) << 1) | msb_step_bit(x, len)
    }
}

// WHAT:
//   Step-accurate long-division state for first `len` high bits.
// WHY:
//   Mirrors the bitwise quotient/remainder updates in BigUint::div_rem.
spec fn div_rem_len_spec(x: u128, d: u128, len: nat) -> (u128, u128)
    recommends
        d > 0,
        len <= 128,
    decreases len
{
    if len == 0 {
        (0u128, 0u128)
    } else {
        let prev = div_rem_len_spec(x, d, (len - 1) as nat);
        let q_prev = prev.0;
        let r_prev = prev.1;
        let bit = msb_step_bit(x, len);
        let q2 = q_prev << 1;
        let r2 = (r_prev << 1) | bit;
        if r2 >= d {
            ((q2 | 1u128), (r2 - d) as u128)
        } else {
            (q2, r2)
        }
    }
}

fn div_rem_len_u128(x: u128, d: u128, len: u32) -> (out: (u128, u128))
    requires
        d > 0,
        len <= 128,
    ensures
        out == div_rem_len_spec(x, d, len as nat),
    decreases len
{
    if len == 0 {
        (0u128, 0u128)
    } else {
        let prev = div_rem_len_u128(x, d, len - 1);
        let q_prev = prev.0;
        let r_prev = prev.1;
        let bit = (x >> (128u32 - len)) & 1u128;
        let q2 = q_prev << 1;
        let r2 = (r_prev << 1) | bit;
        if r2 >= d {
            ((q2 | 1u128), r2 - d)
        } else {
            (q2, r2)
        }
    }
}

// WHAT:
//   Bounded-u128 mirror of BigUint::div_rem.
// WHY:
//   Proves executable conformance to the MSB-first long-division model.
fn div_rem_u128(x: u128, d: u128) -> (out: (u128, u128))
    requires
        d > 0,
    ensures
        out == div_rem_len_spec(x, d, 128),
{
    div_rem_len_u128(x, d, 128)
}

proof fn smoke_prefix_full_width()
{
    assert(prefix_len_spec(0u128, 128) == 0u128) by (compute);
    assert(prefix_len_spec(1u128, 128) == 1u128) by (compute);
    assert(prefix_len_spec(37u128, 128) == 37u128) by (compute);
}

} // verus!
