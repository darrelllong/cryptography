//! Fuzz CtrDrbgAes256: determinism and no-panic guarantees.
//!
//! Invariants:
//! 1. Two instances seeded identically produce identical output.
//! 2. After identical reseeds, output is still identical.
//! 3. reseed_counter increments on each generate call.
#![no_main]

use cryptography::CtrDrbgAes256;
use libfuzzer_sys::fuzz_target;

const SEED: usize = 48;

fuzz_target!(|data: &[u8]| {
    if data.len() < SEED {
        return;
    }
    let seed: [u8; SEED] = data[..SEED].try_into().unwrap();

    let mut rng1 = CtrDrbgAes256::new(&seed);
    let mut rng2 = CtrDrbgAes256::new(&seed);

    let out_len = (data.get(SEED).copied().unwrap_or(64) as usize % 512) + 1;
    let mut out1 = vec![0u8; out_len];
    let mut out2 = vec![0u8; out_len];

    // Invariant 1: identical seeds produce identical output.
    rng1.generate(&mut out1, None);
    rng2.generate(&mut out2, None);
    assert_eq!(out1, out2, "CtrDrbgAes256: determinism violated");

    // Invariant 3: reseed_counter increments after generate.
    let count_before = rng1.reseed_counter();
    rng1.generate(&mut out1, None);
    assert!(
        rng1.reseed_counter() > count_before,
        "CtrDrbgAes256: reseed_counter did not increment after generate",
    );

    // Invariant 2: starting from the *same* initial state + same reseed →
    // identical subsequent output.  We must start fresh RNGs here because rng1
    // and rng2 have diverged (rng1 had an extra generate call for invariant 3).
    if data.len() >= SEED * 2 {
        let reseed: [u8; SEED] = data[SEED..SEED * 2].try_into().unwrap();
        let mut rng3 = CtrDrbgAes256::new(&seed);
        let mut rng4 = CtrDrbgAes256::new(&seed);
        rng3.reseed(&reseed);
        rng4.reseed(&reseed);
        rng3.generate(&mut out1, None);
        rng4.generate(&mut out2, None);
        assert_eq!(out1, out2, "CtrDrbgAes256: determinism violated after reseed");
    }

    // generate with additional input must not panic.
    if data.len() >= SEED * 3 {
        let add: [u8; SEED] = data[SEED * 2..SEED * 3].try_into().unwrap();
        let mut out3 = vec![0u8; out_len];
        rng1.generate(&mut out3, Some(&add));
    }
});
