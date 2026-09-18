//! Interleaved input-class timing experiment for the crate's constant-time
//! claims, after Reparaz, Balasch and Verbauwhede, "Dude, is my code constant
//! time?" (IACR ePrint 2016/1123).
//!
//! `scripts/ct_codegen.sh` reads the machine code and says which conditional
//! branches exist. This measures the running machine instead: it times the
//! same operation over two classes of input that a constant-time
//! implementation must not distinguish, and asks whether the two timing
//! distributions differ.
//!
//! # The protocol, fixed before any run
//!
//! - Each experiment names two input classes. The operation is run
//!   `MEASUREMENTS` times; before each run a fair coin from a seeded CSPRNG
//!   picks the class, so the classes are interleaved and any drift — thermal,
//!   scheduling, frequency — falls on both alike.
//! - Only the operation is timed. Input preparation happens outside the timed
//!   span.
//! - The first `WARMUP` measurements are discarded.
//! - A measurement's tail is dominated by interrupts and preemption, so for
//!   each percentile in `CROPS` the measurements above that percentile are
//!   dropped and Welch's t between the classes is computed on what remains.
//!   The experiment's statistic is the largest `|t|` over the crops.
//! - Each experiment is measured twice over: the statistic on the first
//!   quarter of its measurements, and the statistic on all of them. A real
//!   difference makes `|t|` grow with the square root of the sample size, so
//!   four times the measurements roughly doubles it; noise near the threshold
//!   does not grow.
//! - An experiment is *flagged* when the full statistic exceeds `THRESHOLD`
//!   and either the quarter statistic does too — the difference was there all
//!   along — or the full statistic is at least `GROWTH` times the quarter,
//!   which is how a real difference behaves as the sample grows. The
//!   threshold is dudect's 4.5, `t` for a two-sided test at roughly 1e-5 at
//!   these sample sizes. The second clause is what keeps a statistic that
//!   wanders across the threshold from deciding a run; the first is what
//!   keeps a large, steady difference from being dismissed for not growing
//!   fast enough.
//!
//! # What a run can conclude
//!
//! A flagged real operation is evidence of a timing difference between the
//! classes on this machine and build. An unflagged one is not proof of
//! constant time: it says this experiment, at this sample size, on this
//! machine, did not find a difference.
//!
//! The experiment must also control what happens *around* the timed span. An
//! early version of this program prepared the random class by drawing bytes
//! and the fixed class by not drawing them, and flagged both AES-128 and the
//! X25519 ladder; what it had measured was its own preparation. Both classes
//! now draw the same bytes and copy the same buffers, and a key schedule is
//! built outside the timed span. A later version flipped one byte of a tag
//! per iteration, at a different offset in each class, which stored to that
//! offset immediately before the comparison read the array: the pair
//! differing at bytes 0 and 31 then came out marginally over the threshold on
//! two hosts while the pair differing at bytes 15 and 31 stayed quiet, which
//! is not how an early exit behaves. Every fixture is now built once, and an
//! iteration copies one of them whole.
//!
//! Both classes are also *fixed* values, not one fixed value against fresh
//! random ones. A class that repeats one input leaves the machine in the same
//! state every time — same cache contents, same operands — which a class of
//! fresh values does not, and for an operation as large as a scalar
//! multiplication that difference alone was enough to flag: on an idle Linux
//! host, a fixed scalar against random scalars gave `|t| = 10.4` while two
//! fixed scalars gave 0.9. Two fixed values, chosen to differ in the way the
//! implementation might notice, compare like with like.
//!
//! That is why every run includes a positive control: a byte comparison that
//! stops at the first difference, whose classes differ in where that first
//! difference lies. A run that fails to flag the control has not shown the
//! apparatus can see a leak it is pointed at, and the run's other results say
//! nothing. The exit status is 0 only when the control is flagged and no real
//! operation is.

use std::hint::black_box;
use std::time::Instant;

use cryptography::public_key::ed25519::Ed25519;
use cryptography::{Aes128Ct, ChaCha20, ChaCha20Poly1305, CtrDrbgAes256, Hmac, Sha256};
use cryptography::vt::{MlKem, MlKemCiphertext, MlKemParameterSet, X25519};

/// Timed runs per experiment, before cropping. The statistic is computed on
/// the first quarter of them and on all of them.
const MEASUREMENTS: usize = 800_000;
/// How much the statistic must grow from the quarter to the whole for a
/// difference to count as real: a leak's `|t|` doubles, noise does not.
const GROWTH: f64 = 1.5;
/// Measurements discarded while caches and frequency settle.
const WARMUP: usize = 10_000;
/// Tail percentiles kept, as thousandths, from all of it down to a tenth.
const CROPS: [u32; 10] = [1000, 900, 800, 700, 600, 500, 400, 300, 200, 100];
/// dudect's decision threshold on |t|.
const THRESHOLD: f64 = 4.5;
/// Dense inputs, every byte different from the next: one side of the pairs
/// whose other side is degenerate, and the ordinary value where a pair holds
/// two ordinary ones.
const FIXED_KEY: [u8; 32] = *b"ct_timing fixed class key bytes.";
const FIXED_BLOCK: [u8; 16] = *b"fixed block 0123";
const OTHER_KEY: [u8; 32] = *b"ct_timing other fixed class key.";

/// Two scalars that differ in how often the ladder's conditional swap fires,
/// which is what separated an all-zero scalar from a dense one on one host.
/// Both are ordinary-looking keys: after clamping, the alternating one swaps
/// on almost every round, the run-length one on about a sixth of them.
const ALTERNATING_SCALAR: [u8; 32] = [0x55; 32];
const LONG_RUN_SCALAR: [u8; 32] = [0xf0; 32];

/// A point of small order on Curve25519: `u = 1`, whose ladder output is the
/// all-zero shared secret RFC 7748 §6.1 names.
const LOW_ORDER_POINT: [u8; 32] = {
    let mut u = [0u8; 32];
    u[0] = 1;
    u
};

/// The CSPRNG seed, so a run is reproducible.
const SEED: [u8; 32] = *b"ct_timing interleaved class draw";
/// The ChaCha20 nonce beside it; one stream is drawn per run.
const NONCE: [u8; 12] = *b"ct-timing-v1";

/// Running mean and variance of one class's measurements (Welford).
#[derive(Clone, Copy, Default)]
struct Moments {
    count: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, value: f64) {
        self.count += 1.0;
        let delta = value - self.mean;
        self.mean += delta / self.count;
        self.m2 += delta * (value - self.mean);
    }

    /// Sample variance; zero for fewer than two measurements.
    fn variance(&self) -> f64 {
        if self.count < 2.0 {
            0.0
        } else {
            self.m2 / (self.count - 1.0)
        }
    }
}

/// Welch's t for two samples with unequal variances.
fn welch_t(a: &Moments, b: &Moments) -> f64 {
    if a.count < 2.0 || b.count < 2.0 {
        return 0.0;
    }
    let denominator = (a.variance() / a.count + b.variance() / b.count).sqrt();
    if denominator == 0.0 {
        return 0.0;
    }
    (a.mean - b.mean) / denominator
}

/// One class's measurements, in nanoseconds, in the order they were taken.
struct Samples {
    class: [Vec<f64>; 2],
}

impl Samples {
    fn new() -> Self {
        Self {
            class: [Vec::new(), Vec::new()],
        }
    }

    /// The largest `|t|` over the crops, and the crop that produced it, using
    /// the first `fraction`th of each class's measurements.
    fn statistic_over(&self, fraction: usize) -> (f64, u32) {
        let take = |v: &Vec<f64>| v[..v.len() / fraction].to_vec();
        let kept = [take(&self.class[0]), take(&self.class[1])];
        let mut all: Vec<f64> = kept[0].iter().chain(kept[1].iter()).copied().collect();
        all.sort_by(|x, y| x.partial_cmp(y).expect("timings are finite"));
        let mut best = (0.0f64, CROPS[0]);
        for crop in CROPS {
            let keep = all.len() * crop as usize / 1000;
            if keep < 2 {
                continue;
            }
            let ceiling = all[keep - 1];
            let mut moments = [Moments::default(), Moments::default()];
            for (class, samples) in kept.iter().enumerate() {
                for &value in samples {
                    if value <= ceiling {
                        moments[class].push(value);
                    }
                }
            }
            let t = welch_t(&moments[0], &moments[1]).abs();
            if t > best.0 {
                best = (t, crop);
            }
        }
        best
    }
}

/// The class-drawing CSPRNG: one ChaCha20 stream, read one byte at a time.
struct Coin {
    stream: ChaCha20,
    buffer: [u8; 64],
    next: usize,
}

impl Coin {
    fn new() -> Self {
        Self {
            stream: ChaCha20::new(&SEED, &NONCE),
            buffer: [0u8; 64],
            next: 64,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.next == self.buffer.len() {
            self.buffer = [0u8; 64];
            self.stream.apply_keystream(&mut self.buffer);
            self.next = 0;
        }
        let out = self.buffer[self.next];
        self.next += 1;
        out
    }

    /// One fair bit, as a class index.
    fn class(&mut self) -> usize {
        usize::from(self.byte() & 1)
    }
}

/// Run one experiment: `prepare` builds a class's input outside the timed
/// span, `run` is what gets timed, and the coin picks the class.
fn experiment<T>(
    name: &str,
    classes: [&str; 2],
    coin: &mut Coin,
    mut prepare: impl FnMut(usize) -> T,
    mut run: impl FnMut(&mut T),
) -> (f64, u32) {
    let mut samples = Samples::new();
    for i in 0..MEASUREMENTS {
        let class = coin.class();
        let mut input = prepare(class);
        let start = Instant::now();
        run(black_box(&mut input));
        let elapsed = start.elapsed().as_nanos() as f64;
        if i >= WARMUP {
            samples.class[class].push(elapsed);
        }
    }
    let (quarter, _) = samples.statistic_over(4);
    let (t, crop) = samples.statistic_over(1);
    let flagged = t > THRESHOLD && (quarter > THRESHOLD || t >= GROWTH * quarter);
    let verdict = if flagged {
        "FLAGGED"
    } else if t > THRESHOLD {
        "over threshold but not growing"
    } else {
        "no difference found"
    };
    println!(
        "{name:31} |t| = {t:7.2} (quarter {quarter:6.2}) at crop {crop:4}/1000   {verdict}\n  \
         class 0: {}\n  class 1: {}",
        classes[0], classes[1]
    );
    (if flagged { t } else { 0.0 }, crop)
}

/// The positive control: a comparison that stops at the first differing byte.
/// It must be flagged, or the apparatus has not shown it can see a leak.
fn early_exit_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return false;
        }
    }
    true
}

fn main() {
    println!(
        "measurements: {MEASUREMENTS} per experiment ({WARMUP} discarded), \
         threshold |t| > {THRESHOLD}"
    );
    println!("host build: rustc {}\n", env!("CT_TIMING_RUSTC"));

    let mut coin = Coin::new();
    let mut failures = Vec::new();

    // Positive control: the classes differ in where the first differing byte
    // sits, which an early-exit comparison turns into a timing difference.
    let key = [0x2bu8; 32];
    let message = [0x5au8; 256];
    let reference: [u8; 32] = Hmac::<Sha256>::compute(&key, &message)
        .try_into()
        .expect("HMAC-SHA-256 is 32 bytes");
    // The two classes' tags are built once, here, and each iteration copies
    // one of them whole. Flipping a byte inside the timed loop would store to
    // a different offset per class immediately before the comparison reads
    // the array, and that store, not the comparison, is what the measurement
    // would then see.
    let tag_first = {
        let mut tag = reference;
        tag[0] ^= 0xff;
        tag
    };
    let tag_last = {
        let mut tag = reference;
        let last = tag.len() - 1;
        tag[last] ^= 0xff;
        tag
    };
    let tag_middle = {
        let mut tag = reference;
        let middle = tag.len() / 2 - 1;
        tag[middle] ^= 0xff;
        tag
    };

    let (control, _) = experiment(
        "control: early-exit compare",
        ["differs at byte 0", "differs at byte 31"],
        &mut coin,
        |class| {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(if class == 0 { &tag_first } else { &tag_last });
            tag
        },
        |tag| {
            black_box(early_exit_equal(&reference, tag));
        },
    );
    if control <= THRESHOLD {
        failures.push("the positive control was not flagged: this run shows nothing");
    }

    // Negative control: two classes drawn from the same distribution. Anything
    // flagged here is the apparatus, not the code under test.
    let (null, _) = experiment(
        "control: identical classes",
        ["differs at byte 31", "differs at byte 31"],
        &mut coin,
        |_| {
            let mut tag = reference;
            let last = tag.len() - 1;
            tag[last] ^= 0xff;
            tag
        },
        |tag| {
            black_box(Hmac::<Sha256>::verify(&key, &message, tag));
        },
    );
    if null > THRESHOLD {
        failures.push("the negative control was flagged: the apparatus separates equal classes");
    }

    // The same two classes through the crate's tag verification, which the
    // machine-code evidence says is a branch-free comparison.
    let (verify, _) = experiment(
        "Hmac::<Sha256>::verify",
        ["differs at byte 0", "differs at byte 31"],
        &mut coin,
        |class| {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(if class == 0 { &tag_first } else { &tag_last });
            tag
        },
        |tag| {
            black_box(Hmac::<Sha256>::verify(&key, &message, tag));
        },
    );
    if verify > THRESHOLD {
        failures.push("Hmac::<Sha256>::verify separated the two tag classes");
    }

    // Two fixed keys and blocks, one all-zero and one dense: the bitsliced AES
    // claims the same work whatever the secret is.
    let (aes, _) = experiment(
        "Aes128Ct::encrypt_block",
        ["all-zero key and block", "dense key and block"],
        &mut coin,
        |class| {
            // Both classes copy one fixture, so what precedes the timed span
            // is the same work either way. The key schedule is built here too,
            // so what is timed is the block function alone.
            let mut key = [0u8; 16];
            let mut block = [0u8; 16];
            key.copy_from_slice(if class == 0 { &[0u8; 16] } else { &FIXED_KEY[..16] });
            block.copy_from_slice(if class == 0 { &[0u8; 16] } else { &FIXED_BLOCK });
            (Aes128Ct::new(&key), block)
        },
        |(cipher, block)| {
            black_box(cipher.encrypt_block(block));
        },
    );
    if aes > THRESHOLD {
        failures.push("Aes128Ct::encrypt_block separated the two key classes");
    }

    // A fixed scalar against random ones through the ladder.
    let base = {
        let mut u = [0u8; 32];
        u[0] = 9;
        u
    };
    let (ladder, _) = experiment(
        "X25519::scalar_mult",
        ["scalar of zero bytes", "dense scalar"],
        &mut coin,
        |class| {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(if class == 0 { &[0u8; 32] } else { &FIXED_KEY });
            scalar
        },
        |scalar| {
            black_box(X25519::scalar_mult(scalar, &base));
        },
    );
    if ladder > THRESHOLD {
        failures.push("X25519::scalar_mult separated the two scalar classes");
    }

    // Two fixed scalars against each other: neither class draws fresh values,
    // so a difference here is in the scalars and not in how often the machine
    // sees the same input.
    let (two_fixed, _) = experiment(
        "X25519::scalar_mult (two fixed)",
        ["fixed scalar A", "fixed scalar B"],
        &mut coin,
        |class| {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(if class == 0 { &FIXED_KEY } else { &OTHER_KEY });
            scalar
        },
        |scalar| {
            black_box(X25519::scalar_mult(scalar, &base));
        },
    );
    if two_fixed > THRESHOLD {
        failures.push("X25519::scalar_mult separated two fixed scalars");
    }

    // Two ordinary scalars whose swap counts differ: about 250 rounds against
    // about 40. If a host separates these, the swap pattern is observable for
    // keys a caller would actually use, not only for a degenerate one.
    let (swaps, _) = experiment(
        "X25519::scalar_mult (swap count)",
        ["alternating bits", "long runs"],
        &mut coin,
        |class| {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(if class == 0 {
                &ALTERNATING_SCALAR
            } else {
                &LONG_RUN_SCALAR
            });
            scalar
        },
        |scalar| {
            black_box(X25519::scalar_mult(scalar, &base));
        },
    );
    if swaps > THRESHOLD {
        failures.push("X25519::scalar_mult separated two scalars by their swap counts");
    }

    // The peer's point rather than the scalar: a low-order point, whose ladder
    // state stays degenerate, against a random one. RFC 7748 §6.1 lets the
    // agreement reject the all-zero result, but the ladder that produces it
    // must not take a different amount of time to do so.
    let (points, _) = experiment(
        "X25519::scalar_mult (point)",
        ["low-order point", "ordinary point"],
        &mut coin,
        |class| {
            let mut u = [0u8; 32];
            u.copy_from_slice(if class == 0 { &LOW_ORDER_POINT } else { &base });
            u
        },
        |u| {
            black_box(X25519::scalar_mult(&FIXED_KEY, u));
        },
    );
    if points > THRESHOLD {
        failures.push("X25519::scalar_mult separated the two point classes");
    }

    // A tag differing in its middle byte against one differing in its last: a
    // comparison that stopped early anywhere would separate these too.
    let (middle, _) = experiment(
        "Hmac::<Sha256>::verify (middle)",
        ["differs at byte 15", "differs at byte 31"],
        &mut coin,
        |class| {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(if class == 0 { &tag_middle } else { &tag_last });
            tag
        },
        |tag| {
            black_box(Hmac::<Sha256>::verify(&key, &message, tag));
        },
    );
    if middle > THRESHOLD {
        failures.push("Hmac::<Sha256>::verify separated the middle and last tag classes");
    }

    // A whole AEAD, not a primitive: opening a message whose tag is right
    // against one whose tag is wrong. The tag comparison is the only step that
    // differs, so a difference here is an early exit in the failure path — the
    // one an attacker gets to repeat as often as it likes.
    let aead_key = FIXED_KEY;
    let aead_nonce = [0x5au8; 12];
    let aead_aad = *b"ct_timing associated data";
    let mut aead_message = vec![0u8; 1024];
    for (index, byte) in aead_message.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    let sealed = {
        let mut buffer = aead_message.clone();
        let aead = ChaCha20Poly1305::new(&aead_key);
        let tag = aead.encrypt_in_place(&aead_nonce, &aead_aad, &mut buffer);
        (buffer, tag)
    };
    let mut wrong_tag = sealed.1;
    wrong_tag[0] ^= 0xff;
    let aead = ChaCha20Poly1305::new(&aead_key);
    let (open, _) = experiment(
        "ChaCha20Poly1305::open",
        ["tag accepts", "tag rejects"],
        &mut coin,
        |class| {
            let tag = if class == 0 { sealed.1 } else { wrong_tag };
            (sealed.0.clone(), tag)
        },
        |(buffer, tag)| {
            black_box(aead.decrypt_in_place(&aead_nonce, &aead_aad, buffer, tag));
        },
    );
    if open > THRESHOLD {
        failures.push("ChaCha20Poly1305::open separated an accepted tag from a rejected one");
    }

    // A whole signature under two fixed secret keys, one of them a seed of a
    // single set bit. Signing is deterministic in RFC 8032, so what could
    // differ between the classes is the fixed-base multiplication by the
    // scalar each seed derives.
    let dense_seed = FIXED_KEY;
    let mut sparse_seed = [0u8; 32];
    sparse_seed[0] = 1;
    let (_, dense_key) = Ed25519::from_seed(dense_seed);
    let (_, sparse_key) = Ed25519::from_seed(sparse_seed);
    let signed_message = aead_message.clone();
    let (sign, _) = experiment(
        "Ed25519::sign_message",
        ["dense seed", "one-bit seed"],
        &mut coin,
        // The key is chosen in the preparation, so what the timed span holds
        // is one signature and nothing else.
        |class| {
            if class == 0 {
                &dense_key
            } else {
                &sparse_key
            }
        },
        |key| {
            black_box(key.sign_message(&signed_message));
        },
    );
    if sign > THRESHOLD {
        failures.push("Ed25519::sign_message separated the two secret keys");
    }

    // ML-KEM decapsulation of a well-formed ciphertext against a tampered one.
    // FIPS 203 §7.3 decapsulates both and selects the shared secret under a
    // mask, so the two must take the same time; the fallback is what implicit
    // rejection is for.
    // The DRBG that builds the fixtures: seeded from the same constant, so a
    // run's key pair and ciphertext are the same every time.
    let mut drbg_seed = [0u8; 48];
    drbg_seed[..SEED.len()].copy_from_slice(&SEED);
    drbg_seed[SEED.len()..].copy_from_slice(&FIXED_BLOCK);
    let mut drbg = CtrDrbgAes256::new(&drbg_seed);
    let (public_key, private_key) =
        MlKem::keygen(MlKemParameterSet::MlKem768, &mut drbg).expect("key pair");
    let (ciphertext, _) = MlKem::encaps(&public_key, &mut drbg);
    let good_wire = ciphertext.to_wire_bytes();
    let (kem, _) = experiment(
        "MlKem::decaps",
        ["well-formed ciphertext", "tampered ciphertext"],
        &mut coin,
        |class| {
            let mut wire = good_wire.clone();
            if class == 1 {
                wire[0] ^= 1;
            }
            MlKemCiphertext::from_wire_bytes(MlKemParameterSet::MlKem768, &wire)
                .expect("ciphertext of the right length")
        },
        |ciphertext| {
            black_box(MlKem::decaps(&private_key, ciphertext));
        },
    );
    if kem > THRESHOLD {
        failures.push("MlKem::decaps separated well-formed from tampered ciphertexts");
    }

    if failures.is_empty() {
        println!("\nthe control was flagged and no operation under test was");
        return;
    }
    println!();
    for failure in &failures {
        println!("FAILURE: {failure}");
    }
    std::process::exit(1);
}
