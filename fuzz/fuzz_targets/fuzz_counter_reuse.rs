//! Keystream counters across calls: a second call must continue the stream,
//! never restart it.
//!
//! Layout: `[selector][32-byte key][24-byte nonce][4-byte counter][data]`.
//! The low bits of the selector pick the cipher; the rest is split into chunks
//! whose sizes come from the data's own length, so a call boundary falls at
//! every offset the fuzzer can reach.
//!
//! What must hold: encrypting in chunks equals encrypting in one call, since a
//! restarted counter would repeat keystream from the second chunk on; a stream
//! advanced `m` blocks equals one started `m` blocks later, which is the same
//! statement about the counter arithmetic; the remaining-keystream count falls
//! by exactly what was taken; and CTR mode, whose counter the caller carries,
//! agrees with itself across a block-aligned split.
#![no_main]

use cryptography::{Aes128, BlockCipher, ChaCha20, Ctr, XChaCha20};
use libfuzzer_sys::fuzz_target;

/// ChaCha20's block, and the unit its 32-bit counter counts.
const BLOCK: usize = 64;
const KEY_LEN: usize = 32;
const XNONCE_LEN: usize = 24;
const COUNTER_LEN: usize = 4;
const HEADER: usize = KEY_LEN + XNONCE_LEN + COUNTER_LEN;

/// Split `len` into chunks. The sizes come from the input itself, so the
/// boundaries land anywhere: mid-block, on a block, and past several.
fn chunks(len: usize, seed: u8) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut left = len;
    let mut step = usize::from(seed) + 1;
    while left > 0 {
        let take = step.min(left);
        sizes.push(take);
        left -= take;
        step = step * 2 + 1;
    }
    sizes
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if rest.len() < HEADER {
        return;
    }
    let (key, rest) = rest.split_at(KEY_LEN);
    let (nonce, rest) = rest.split_at(XNONCE_LEN);
    let (counter_bytes, message) = rest.split_at(COUNTER_LEN);
    let key: [u8; KEY_LEN] = key.try_into().expect("32 bytes");
    let xnonce: [u8; XNONCE_LEN] = nonce.try_into().expect("24 bytes");
    let nonce: [u8; 12] = nonce[..12].try_into().expect("12 bytes");
    let counter = u32::from_be_bytes(counter_bytes.try_into().expect("4 bytes"));
    if message.is_empty() {
        return;
    }

    // Keep the stream inside the counter's range: the crate panics rather
    // than wrap, which its own tests pin, and this target is about the calls
    // before that point.
    let blocks_needed = u32::try_from(message.len().div_ceil(BLOCK)).unwrap_or(u32::MAX);
    let counter = counter.min(u32::MAX - blocks_needed.saturating_add(1));

    match selector % 3 {
        0 => {
            let mut whole = message.to_vec();
            ChaCha20::with_counter(&key, &nonce, counter).apply_keystream(&mut whole);

            let mut piecewise = message.to_vec();
            let mut cipher = ChaCha20::with_counter(&key, &nonce, counter);
            let mut remaining = cipher.keystream_remaining();
            let mut at = 0;
            for size in chunks(message.len(), selector) {
                cipher.apply_keystream(&mut piecewise[at..at + size]);
                at += size;
                let now = cipher.keystream_remaining();
                assert_eq!(
                    remaining - now,
                    size as u64,
                    "ChaCha20: the remaining keystream did not fall by what was taken"
                );
                remaining = now;
            }
            assert_eq!(
                piecewise, whole,
                "ChaCha20: chunked encryption differs from one call"
            );

            // A stream advanced m whole blocks is a stream that started m
            // blocks later.
            let advance = u32::from(selector) % 64;
            if counter <= u32::MAX - advance - blocks_needed {
                let mut skipped = vec![0u8; advance as usize * BLOCK];
                let mut cipher = ChaCha20::with_counter(&key, &nonce, counter);
                cipher.keystream(&mut skipped);
                let mut after = message.to_vec();
                cipher.apply_keystream(&mut after);

                let mut started_later = message.to_vec();
                ChaCha20::with_counter(&key, &nonce, counter + advance)
                    .apply_keystream(&mut started_later);
                assert_eq!(
                    after, started_later,
                    "ChaCha20: advancing the counter is not starting later"
                );
            }
        }
        1 => {
            let mut whole = message.to_vec();
            XChaCha20::with_counter(&key, &xnonce, counter).apply_keystream(&mut whole);

            let mut piecewise = message.to_vec();
            let mut cipher = XChaCha20::with_counter(&key, &xnonce, counter);
            let mut at = 0;
            for size in chunks(message.len(), selector) {
                cipher.apply_keystream(&mut piecewise[at..at + size]);
                at += size;
            }
            assert_eq!(
                piecewise, whole,
                "XChaCha20: chunked encryption differs from one call"
            );
        }
        _ => {
            // CTR mode carries its counter in the caller's buffer, so the
            // property is that a block-aligned split with the counter advanced
            // by the blocks consumed agrees with one call.
            let block = <Aes128 as BlockCipher>::BLOCK_LEN;
            if message.len() <= block {
                return;
            }
            let key: [u8; 16] = key[..16].try_into().expect("16 bytes");
            let mode = Ctr::new(Aes128::new(&key));
            let mut start = [0u8; 16];
            start.copy_from_slice(&xnonce[..16]);

            let mut whole = message.to_vec();
            mode.apply_keystream(&start, &mut whole);

            let split = (usize::from(selector) % (message.len() / block)).max(1) * block;
            let mut piecewise = message.to_vec();
            mode.apply_keystream(&start, &mut piecewise[..split]);
            let mut advanced = start;
            for _ in 0..split / block {
                for byte in advanced.iter_mut().rev() {
                    *byte = byte.wrapping_add(1);
                    if *byte != 0 {
                        break;
                    }
                }
            }
            mode.apply_keystream(&advanced, &mut piecewise[split..]);
            assert_eq!(
                piecewise, whole,
                "CTR: a block-aligned split differs from one call"
            );
        }
    }
});
