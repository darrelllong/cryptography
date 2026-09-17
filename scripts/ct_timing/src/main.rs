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
//! - An experiment is *flagged* when that statistic exceeds `THRESHOLD`. The
//!   threshold is dudect's 4.5, which is `t` for a two-sided test at roughly
//!   1e-5 with these sample sizes.
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
//! now draw the same bytes and copy the same buffers, and the key schedule is
//! built outside the timed span, so what differs between the classes is the
//! value the operation is given and nothing else.
//!
//! That is why every run includes a positive control: a byte comparison that
//! stops at the first difference, whose classes differ in where that first
//! difference lies. A run that fails to flag the control has not shown the
//! apparatus can see a leak it is pointed at, and the run's other results say
//! nothing. The exit status is 0 only when the control is flagged and no real
//! operation is.

use std::hint::black_box;
use std::time::Instant;

use cryptography::{Aes128Ct, ChaCha20, Hmac, Sha256};
use cryptography::vt::X25519;

/// Timed runs per experiment, before cropping.
const MEASUREMENTS: usize = 200_000;
/// Measurements discarded while caches and frequency settle.
const WARMUP: usize = 10_000;
/// Tail percentiles kept, as thousandths, from all of it down to a tenth.
const CROPS: [u32; 10] = [1000, 900, 800, 700, 600, 500, 400, 300, 200, 100];
/// dudect's decision threshold on |t|.
const THRESHOLD: f64 = 4.5;
/// The fixed class's inputs: arbitrary constants, not all-zero. A degenerate
/// input can be faster for reasons that have nothing to do with a branch on a
/// secret — a multiplier that shortcuts zero operands, for one — and that
/// would be a difference in the data, not in the code under test.
const FIXED_KEY: [u8; 32] = *b"ct_timing fixed class key bytes.";
const FIXED_BLOCK: [u8; 16] = *b"fixed block 0123";

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

    /// The largest `|t|` over the crops, and the crop that produced it.
    fn statistic(&self) -> (f64, u32) {
        let mut all: Vec<f64> = self.class[0].iter().chain(self.class[1].iter()).copied().collect();
        all.sort_by(|x, y| x.partial_cmp(y).expect("timings are finite"));
        let mut best = (0.0f64, CROPS[0]);
        for crop in CROPS {
            let keep = all.len() * crop as usize / 1000;
            if keep < 2 {
                continue;
            }
            let ceiling = all[keep - 1];
            let mut moments = [Moments::default(), Moments::default()];
            for (class, samples) in self.class.iter().enumerate() {
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

    fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = self.byte();
        }
    }

    /// One fair bit, as a class index.
    fn class(&mut self) -> usize {
        usize::from(self.byte() & 1)
    }
}

/// Run one experiment: `prepare` builds the inputs for a class outside the
/// timed span, `run` is what gets timed.
fn experiment<T>(
    name: &str,
    classes: [&str; 2],
    coin: &mut Coin,
    mut prepare: impl FnMut(usize, &mut Coin) -> T,
    mut run: impl FnMut(&T),
) -> (f64, u32) {
    let mut samples = Samples::new();
    for i in 0..MEASUREMENTS {
        let class = coin.class();
        let input = prepare(class, coin);
        let start = Instant::now();
        run(black_box(&input));
        let elapsed = start.elapsed().as_nanos() as f64;
        if i >= WARMUP {
            samples.class[class].push(elapsed);
        }
    }
    let (t, crop) = samples.statistic();
    let verdict = if t > THRESHOLD { "FLAGGED" } else { "no difference found" };
    println!(
        "{name:28} |t| = {t:7.2} at crop {crop:4}/1000   {verdict}\n  \
         class 0: {}\n  class 1: {}",
        classes[0], classes[1]
    );
    (t, crop)
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
    let (control, _) = experiment(
        "control: early-exit compare",
        ["differs at byte 0", "differs at byte 31"],
        &mut coin,
        |class, _| {
            let mut tag = reference;
            let position = if class == 0 { 0 } else { tag.len() - 1 };
            tag[position] ^= 0xff;
            tag
        },
        |tag| {
            black_box(early_exit_equal(&reference, tag));
        },
    );
    if control <= THRESHOLD {
        failures.push("the positive control was not flagged: this run shows nothing");
    }

    // The same two classes through the crate's tag verification, which the
    // machine-code evidence says is a branch-free comparison.
    let (verify, _) = experiment(
        "Hmac::<Sha256>::verify",
        ["differs at byte 0", "differs at byte 31"],
        &mut coin,
        |class, _| {
            let mut tag = reference;
            let position = if class == 0 { 0 } else { tag.len() - 1 };
            tag[position] ^= 0xff;
            tag
        },
        |tag| {
            black_box(Hmac::<Sha256>::verify(&key, &message, tag));
        },
    );
    if verify > THRESHOLD {
        failures.push("Hmac::<Sha256>::verify separated the two tag classes");
    }

    // A fixed key and block against random ones: the bitsliced AES claims the
    // same work whatever the secret is.
    let (aes, _) = experiment(
        "Aes128Ct::encrypt_block",
        ["fixed key and block", "random key and block"],
        &mut coin,
        |class, coin| {
            // Both classes do the same work before the timed span: draw the
            // same bytes, then copy once from the class's source. The key
            // schedule is built here too, so what is timed is the block
            // function alone.
            let mut drawn_key = [0u8; 16];
            let mut drawn_block = [0u8; 16];
            coin.fill(&mut drawn_key);
            coin.fill(&mut drawn_block);
            let mut key = [0u8; 16];
            let mut block = [0u8; 16];
            key.copy_from_slice(if class == 0 {
                &FIXED_KEY[..16]
            } else {
                &drawn_key
            });
            block.copy_from_slice(if class == 0 {
                &FIXED_BLOCK
            } else {
                &drawn_block
            });
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
        ["fixed scalar", "random scalar"],
        &mut coin,
        |class, coin| {
            let mut drawn = [0u8; 32];
            coin.fill(&mut drawn);
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(if class == 0 { &FIXED_KEY } else { &drawn });
            scalar
        },
        |scalar| {
            black_box(X25519::scalar_mult(scalar, &base));
        },
    );
    if ladder > THRESHOLD {
        failures.push("X25519::scalar_mult separated the two scalar classes");
    }

    // The peer's point rather than the scalar: a low-order point, whose ladder
    // state stays degenerate, against a random one. RFC 7748 §6.1 lets the
    // agreement reject the all-zero result, but the ladder that produces it
    // must not take a different amount of time to do so.
    let (points, _) = experiment(
        "X25519::scalar_mult (point)",
        ["low-order point", "random point"],
        &mut coin,
        |class, coin| {
            let mut drawn = [0u8; 32];
            coin.fill(&mut drawn);
            let mut u = [0u8; 32];
            u.copy_from_slice(if class == 0 { &LOW_ORDER_POINT } else { &drawn });
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
        |class, _| {
            let mut tag = reference;
            let position = if class == 0 {
                tag.len() / 2 - 1
            } else {
                tag.len() - 1
            };
            tag[position] ^= 0xff;
            tag
        },
        |tag| {
            black_box(Hmac::<Sha256>::verify(&key, &message, tag));
        },
    );
    if middle > THRESHOLD {
        failures.push("Hmac::<Sha256>::verify separated the middle and last tag classes");
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
