//! `CtrDrbgAes256` against the shape SP 800-90A Rev. 1 gives it, from
//! fuzzer-chosen seeds, strings and request lengths.
//!
//! Layout: `[48-byte seed][u16 request length][48-byte reseed][string of up
//! to 48 bytes]`. Properties, each derived here independently of the DRBG:
//! `instantiate(e, s)` is `new(e XOR (s ‖ 0…))` (§10.2.1.3.1 steps 2-3);
//! `reseed_with_additional_input(e, s)` is `reseed(e XOR (s ‖ 0…))`
//! (§10.2.1.4.1 steps 2-3); a request of `k` bytes returns the first `k`
//! bytes of a longer request from the same state (§10.2.1.5.1 step 4 takes
//! the leftmost bits of the block stream), for every `k` up to the 64 KiB
//! maximum; and the reseed counter is 1 after a reseed and grows by one per
//! request.
#![no_main]

use cryptography::CtrDrbgAes256;
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;
const MAX_REQUEST: usize = 1 << 16;

fn xor_padded(entropy: &[u8; SEED], string: &[u8]) -> [u8; SEED] {
    let mut out = *entropy;
    for (byte, extra) in out.iter_mut().zip(string) {
        *byte ^= extra;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED + 2 {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().expect("48 bytes");
    let request = usize::from(u16::from_be_bytes([data[SEED], data[SEED + 1]])) + 1;
    let rest = &data[SEED + 2..];
    let (fresh, string) = if rest.len() >= SEED {
        let fresh: [u8; SEED] = rest[..SEED].try_into().expect("48 bytes");
        (fresh, &rest[SEED..rest.len().min(2 * SEED)])
    } else {
        ([0x5Au8; SEED], &rest[..rest.len().min(SEED)])
    };

    // Instantiate with a personalization string is `new` on the XORed seed.
    let mut a = CtrDrbgAes256::instantiate(&seed, string);
    let mut b = CtrDrbgAes256::new(&xor_padded(&seed, string));
    let (mut out_a, mut out_b) = (vec![0u8; request], vec![0u8; request]);
    a.generate(&mut out_a, None);
    b.generate(&mut out_b, None);
    assert_eq!(
        out_a, out_b,
        "CTR_DRBG: instantiate is not new on the padded XOR"
    );
    assert_eq!(
        a.reseed_counter(),
        2,
        "CTR_DRBG: one request after instantiation"
    );

    // A shorter request is a prefix of a longer one from the same state.
    let mut short = CtrDrbgAes256::new(&seed);
    let mut long = CtrDrbgAes256::new(&seed);
    let (mut out_short, mut out_long) = (vec![0u8; request], vec![0u8; MAX_REQUEST]);
    short.generate(&mut out_short, Some(string));
    long.generate(&mut out_long, Some(string));
    assert_eq!(
        out_short[..],
        out_long[..request],
        "CTR_DRBG: a request is not a prefix of a longer one"
    );

    // Reseed with additional input is `reseed` on the XORed seed.
    a.reseed_with_additional_input(&fresh, string);
    b.reseed(&xor_padded(&fresh, string));
    assert_eq!(
        a.reseed_counter(),
        1,
        "CTR_DRBG: reseed does not reset the counter"
    );
    a.generate(&mut out_a, None);
    b.generate(&mut out_b, None);
    assert_eq!(
        out_a, out_b,
        "CTR_DRBG: reseed_with_additional_input is not reseed on the padded XOR"
    );
    assert_eq!(a.reseed_counter(), 2);
});
