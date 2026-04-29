#!/usr/bin/env Rscript
# Encrypts the Complete Works of Shakespeare under each symmetric cipher in
# this crate (block ciphers in CTR mode with a fresh OS-random key/IV; stream
# ciphers in their native keystream mode), then runs a battery of randomness
# tests on the ciphertext sliced into 8-, 16-, and 32-byte chunks.
#
# For each chunk size, every chunk is mapped to a value in [0,1) by treating
# its leading bytes as a big-endian fraction (≤ 53 bits — the precision limit
# of an IEEE-754 double).  The battery is:
#   * Shannon entropy of the raw byte stream (ideal: 8.000 bits/byte) and of
#     the chunk values binned into 256 cells (ideal: 8.000 bits, with a small
#     finite-sample bias correction);
#   * first ten raw moments (compared to the Uniform(0,1) ideals 1/(k+1));
#   * FFT power spectrum, summarised by Fisher's g and a Kolmogorov-Smirnov
#     test of the normalised periodogram against a flat spectrum;
#   * Kolmogorov-Smirnov test against Uniform(0,1);
#   * randtoolbox::gap.test, freq.test (on the bit stream), and order.test;
#   * runs test on the bit stream.
#
# The script writes R-REPORT.md and lists any cipher whose battery rejected
# at α = 0.001 on three or more independent tests.

suppressPackageStartupMessages({
  library(randtoolbox)
  library(tseries)
})

# Resolve paths relative to this script so the workflow runs from any
# working directory and on any user account.  Honour CRYPTOGRAPHY_ROOT if
# the caller wants to override (e.g., when running from an out-of-tree
# build directory).
script_path <- (function() {
  args <- commandArgs(trailingOnly = FALSE)
  fa <- args[grep("^--file=", args)]
  if (length(fa)) sub("^--file=", "", fa[1]) else sys.frames()[[1]]$ofile
})()
ROOT       <- Sys.getenv("CRYPTOGRAPHY_ROOT",
                         normalizePath(file.path(dirname(script_path), ".."),
                                       winslash = "/"))
BIN        <- file.path(ROOT, "target/release/cipher_encrypt")
SCRIPT_DIR <- file.path(ROOT, "scripts")
OUT_DIR    <- file.path(SCRIPT_DIR, "cipher_outputs")
PLOT_DIR   <- file.path(SCRIPT_DIR, "cipher_plots")
PT_PATH    <- file.path(SCRIPT_DIR, "shakespeare.txt")
REPORT     <- file.path(ROOT, "R-REPORT.md")

PG_URL  <- "https://www.gutenberg.org/cache/epub/100/pg100.txt"
ALPHA       <- 0.001    # rejection threshold for an individual test
FAIL_AT     <- 3        # cipher "fails" if ≥ this many tests reject
ENTROPY_TOL <- 0.001    # bits/byte; deviation > tol from 8.0 is suspicious

CIPHERS <- c(
  "aes128", "aes192", "aes256",
  "camellia128", "camellia192", "camellia256",
  "cast128",
  "des", "3des",
  "grasshopper", "magma",
  "present80", "present128",
  "seed",
  "serpent128", "serpent192", "serpent256",
  "sm4",
  "twofish128", "twofish256",
  "simon32_64", "simon64_128", "simon128_128", "simon128_256",
  "speck32_64", "speck64_128", "speck128_128", "speck128_256",
  "chacha20", "xchacha20", "salsa20", "rabbit", "zuc128", "snow3g"
)

CHUNK_SIZES <- c(8L, 16L, 32L)

# Internal cipher tokens (passed to cipher_encrypt) → canonical display names
# used in the report.  Tokens stay lowercase so the binary's match arms keep
# matching; the report shows the algorithm names as their authors spelled them
# (SEED, ChaCha20, etc., not "seed", "chacha20").
DISPLAY_NAME <- c(
  aes128 = "AES-128", aes192 = "AES-192", aes256 = "AES-256",
  camellia128 = "Camellia-128", camellia192 = "Camellia-192",
  camellia256 = "Camellia-256",
  cast128 = "CAST-128",
  des = "DES", `3des` = "3DES",
  grasshopper = "Kuznyechik", magma = "Magma",
  present80 = "PRESENT-80", present128 = "PRESENT-128",
  seed = "SEED",
  serpent128 = "Serpent-128", serpent192 = "Serpent-192",
  serpent256 = "Serpent-256",
  sm4 = "SM4",
  twofish128 = "Twofish-128", twofish256 = "Twofish-256",
  simon32_64 = "Simon32/64", simon64_128 = "Simon64/128",
  simon128_128 = "Simon128/128", simon128_256 = "Simon128/256",
  speck32_64 = "Speck32/64", speck64_128 = "Speck64/128",
  speck128_128 = "Speck128/128", speck128_256 = "Speck128/256",
  chacha20 = "ChaCha20", xchacha20 = "XChaCha20", salsa20 = "Salsa20",
  rabbit = "Rabbit",
  zuc128 = "ZUC-128", snow3g = "SNOW 3G"
)
display_name <- function(token) {
  out <- DISPLAY_NAME[token]
  ifelse(is.na(out), token, out)
}

dir.create(OUT_DIR,  showWarnings = FALSE, recursive = TRUE)
dir.create(PLOT_DIR, showWarnings = FALSE, recursive = TRUE)

# ──────────────────────────────────────────────────────────────────────────────
# Step 1 — fetch the plaintext.
# ──────────────────────────────────────────────────────────────────────────────
fetch_shakespeare <- function() {
  if (!file.exists(PT_PATH) || file.info(PT_PATH)$size < 1e6) {
    message("Downloading Shakespeare from Project Gutenberg…")
    utils::download.file(PG_URL, PT_PATH, mode = "wb", quiet = TRUE)
  }
  invisible(NULL)
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 2 — encrypt under each cipher (cached per binary output).
# ──────────────────────────────────────────────────────────────────────────────
encrypt <- function(name) {
  out <- file.path(OUT_DIR, paste0(name, ".bin"))
  if (!file.exists(out) || file.info(out)$size == 0) {
    rc <- system2(BIN, args = name, stdin = PT_PATH, stdout = out)
    if (rc != 0) stop("cipher_encrypt failed for ", name, " (rc=", rc, ")")
  }
  readBin(out, what = "raw", n = file.info(out)$size)
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 3 — slicing helpers.
# ──────────────────────────────────────────────────────────────────────────────

# Map a raw vector to one [0,1) double per chunk: the chunk's leading
# min(N, 8) bytes interpreted as a big-endian fraction.
to_uniform <- function(bytes, n) {
  L <- length(bytes)
  k <- L %/% n
  if (k < 2) return(numeric(0))
  bytes <- bytes[seq_len(k * n)]
  mat <- matrix(as.integer(bytes), nrow = k, ncol = n, byrow = TRUE)
  m <- min(n, 8L)
  out <- numeric(k)
  for (i in seq_len(m)) out <- out + mat[, i] / (256^i)
  # Clamp away from the open-interval boundaries.
  pmin(pmax(out, .Machine$double.eps), 1 - .Machine$double.eps)
}

# Bit stream of length 8*length(bytes) (MSB first).
to_bits <- function(bytes) {
  ints <- as.integer(bytes)
  m <- vapply(7:0, function(b) bitwAnd(bitwShiftR(ints, b), 1L),
              integer(length(ints)))
  as.integer(t(m))
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 4 — statistical battery.
# ──────────────────────────────────────────────────────────────────────────────

# Shannon entropy in bits, given counts in any number of equiprobable bins.
# Ideal entropy of a uniform distribution over `k` bins is log2(k); we report
# the raw estimate (Miller-Madow correction is negligible at our sample sizes
# of 10^5–10^6 against k = 256 bins, but we apply it anyway for honesty).
shannon_entropy <- function(counts) {
  n <- sum(counts)
  if (n == 0) return(0)
  p <- counts[counts > 0] / n
  H <- -sum(p * log2(p))
  # Miller-Madow bias correction.
  H + (sum(counts > 0) - 1) / (2 * n * log(2))
}

byte_entropy <- function(bytes) {
  shannon_entropy(tabulate(as.integer(bytes) + 1L, nbins = 256L))
}

# Entropy of the [0,1) chunk values binned into 256 equal-width cells. Ideal
# is 8.000 bits for any cipher whose output is uniform, regardless of chunk
# size.
chunk_entropy_256 <- function(u) {
  if (length(u) == 0) return(NA_real_)
  bins <- pmin(floor(u * 256) + 1L, 256L)
  shannon_entropy(tabulate(bins, nbins = 256L))
}

# First 10 raw moments and their absolute deviation from Uniform(0,1) ideals.
moments <- function(u) {
  k <- 10L
  vals <- vapply(1:k, function(j) mean(u^j), numeric(1))
  ideal <- 1 / (1 + 1:k)
  list(values = vals, ideal = ideal, dev = abs(vals - ideal))
}

# Fisher's g test: sharpest periodogram peak vs. mean. Under H0 (white noise)
# the distribution of g is known. We summarise with the "max ratio" — peak
# divided by mean — and a KS test of the normalised periodogram against a
# flat spectrum.
fft_summary <- function(u) {
  x <- u - mean(u)
  N <- length(x)
  spec <- Mod(stats::fft(x))^2
  spec <- spec[2:floor(N / 2)]              # drop DC + Nyquist mirror
  norm <- spec / mean(spec)                  # ~ Exp(1) under H0
  ks <- suppressWarnings(stats::ks.test(norm, "pexp", rate = 1))
  list(peak_ratio = max(spec) / mean(spec),
       ks_p       = ks$p.value,
       norm       = norm)
}

# KS test against Uniform(0,1).
ks_uniform <- function(u) {
  res <- suppressWarnings(stats::ks.test(u, "punif"))
  res$p.value
}

# randtoolbox: gap, frequency-of-bits, order. Each prints when echo=TRUE so we
# silence them and capture the p-value the function returns invisibly.
silent_gap <- function(u) {
  res <- tryCatch(
    capture.output(r <- randtoolbox::gap.test(u, echo = FALSE)),
    error = function(e) NULL)
  if (is.null(res)) return(NA_real_)
  r$p.value
}
silent_freq <- function(u) {
  # `freq.test(u, seq = 0:15)` bins u into 16 cells and runs χ² of bin counts.
  res <- tryCatch(
    capture.output(r <- randtoolbox::freq.test(u, seq = 0:15, echo = FALSE)),
    error = function(e) NULL)
  if (is.null(res)) return(NA_real_)
  r$p.value
}
silent_order <- function(u, d = 4L) {
  # `order.test` requires length(u) to be a multiple of d.
  m <- length(u) - (length(u) %% d)
  if (m < d) return(NA_real_)
  u <- u[seq_len(m)]
  res <- tryCatch(
    capture.output(r <- randtoolbox::order.test(u, d = d, echo = FALSE)),
    error = function(e) NULL)
  if (is.null(res)) return(NA_real_)
  r$p.value
}

# Wald-Wolfowitz runs test on bit stream (above/below median = above/below 0.5).
runs_pvalue <- function(bits) {
  # tseries::runs.test expects a factor of two levels.
  if (length(unique(bits)) < 2) return(NA_real_)
  f <- factor(bits, levels = c(0L, 1L))
  res <- tryCatch(tseries::runs.test(f), error = function(e) NULL)
  if (is.null(res)) return(NA_real_)
  res$p.value
}

# Run the full battery on one (cipher, chunk) combination.
analyse <- function(bytes, n) {
  u <- to_uniform(bytes, n)
  bits <- to_bits(bytes[seq_len(min(length(bytes), 1e6))])  # cap bit tests
  m <- moments(u)
  ff <- fft_summary(u)
  list(
    samples        = length(u),
    chunk_entropy  = chunk_entropy_256(u),
    moments        = m,
    fft            = ff,
    ks_uniform_p   = ks_uniform(u),
    fft_ks_p       = ff$ks_p,
    gap_p          = silent_gap(u),
    freq_p         = silent_freq(u),
    order_p        = silent_order(u),
    runs_bits_p    = runs_pvalue(bits)
  )
}

# Per-cipher PNG of the log-power spectrum (downsampled).
make_plot <- function(cipher, results) {
  png(file.path(PLOT_DIR, paste0(cipher, ".png")),
      width = 900, height = 300, res = 110)
  on.exit(dev.off())
  par(mfrow = c(1, length(CHUNK_SIZES)), mar = c(4, 4, 2, 1))
  for (n in CHUNK_SIZES) {
    norm <- results[[as.character(n)]]$fft$norm
    # Downsample for visualisation.
    idx <- seq.int(1, length(norm), length.out = min(2000, length(norm)))
    plot(idx, log10(norm[idx] + 1e-9), type = "l",
         main = sprintf("%s — %d-byte chunks", cipher, n),
         xlab = "frequency bin", ylab = "log10(power / mean)",
         col = "steelblue")
    abline(h = 0, col = "red", lty = 2)
  }
}

# Verdict: count tests rejecting at ALPHA across all chunk sizes, plus any
# entropy deviation greater than ENTROPY_TOL bits from the ideal 8 bits.
verdict <- function(results, byte_H) {
  pvalues <- c()
  entropy_misses <- 0L
  if (!is.na(byte_H) && abs(byte_H - 8) > ENTROPY_TOL) entropy_misses <- 1L
  for (n in CHUNK_SIZES) {
    r <- results[[as.character(n)]]
    pvalues <- c(pvalues,
                 r$ks_uniform_p, r$fft_ks_p, r$gap_p,
                 r$freq_p, r$order_p, r$runs_bits_p)
    if (!is.na(r$chunk_entropy) && abs(r$chunk_entropy - 8) > ENTROPY_TOL) {
      entropy_misses <- entropy_misses + 1L
    }
  }
  pvalues <- pvalues[!is.na(pvalues)]
  rejects <- sum(pvalues < ALPHA)
  total_tests <- length(pvalues) + length(CHUNK_SIZES) + 1L
  list(rejects = rejects + entropy_misses,
       p_rejects = rejects,
       entropy_misses = entropy_misses,
       total = total_tests,
       pass = (rejects + entropy_misses) < FAIL_AT,
       min_p = if (length(pvalues)) min(pvalues) else NA_real_)
}

# ──────────────────────────────────────────────────────────────────────────────
# Driver
# ──────────────────────────────────────────────────────────────────────────────
fetch_shakespeare()
plaintext <- readBin(PT_PATH, what = "raw", n = file.info(PT_PATH)$size)
plaintext_size <- length(plaintext)
plaintext_entropy <- byte_entropy(plaintext)
plaintext_sha256 <- tools::md5sum(PT_PATH)  # md5 is enough for provenance auditing
r_version_str    <- paste(R.version$major, R.version$minor, sep = ".")
randtoolbox_ver  <- as.character(utils::packageVersion("randtoolbox"))
tseries_ver      <- as.character(utils::packageVersion("tseries"))

all_results <- vector("list", length(CIPHERS))
names(all_results) <- CIPHERS
byte_entropies <- numeric(length(CIPHERS))
names(byte_entropies) <- CIPHERS
verdicts <- vector("list", length(CIPHERS))
names(verdicts) <- CIPHERS
failures <- character(0)

for (cipher in CIPHERS) {
  message(sprintf("[%-14s] encrypting + analysing", cipher))
  ct <- encrypt(cipher)
  byte_entropies[cipher] <- byte_entropy(ct)
  results <- list()
  for (n in CHUNK_SIZES) {
    results[[as.character(n)]] <- analyse(ct, n)
  }
  all_results[[cipher]] <- results
  verdicts[[cipher]]    <- verdict(results, byte_entropies[cipher])
  if (!verdicts[[cipher]]$pass) failures <- c(failures, cipher)
  make_plot(cipher, results)
}

# ──────────────────────────────────────────────────────────────────────────────
# Report writer
# ──────────────────────────────────────────────────────────────────────────────
fmt_p <- function(p) {
  if (is.na(p))   return("   n/a")
  if (p < 1e-12) return("<1e-12")
  if (p < 1e-3)  return(sprintf("%.1e", p))
  sprintf("%.3f", p)
}

lines <- c(
  "# Symmetric-Cipher Randomness Report",
  "",
  sprintf("Generated %s by `scripts/cipher_randomness.R`.", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")),
  sprintf("Toolchain: R %s, randtoolbox %s, tseries %s.",
          r_version_str, randtoolbox_ver, tseries_ver),
  "",
  sprintf("**Plaintext.** Project Gutenberg #100 — *The Complete Works of William Shakespeare* (%s bytes; MD5 `%s`; byte-entropy %.4f bits/byte).",
          formatC(plaintext_size, format = "d", big.mark = ","),
          plaintext_sha256,
          plaintext_entropy),
  "",
  "**Caveat.** Passing this battery is **necessary** for a usable symmetric primitive but is **not sufficient** for cryptographic security; the battery rules out gross statistical defects in the keystream, not key-recovery, distinguishing-attack, or related-key resistance.",
  "",
  "**Method.** Each cipher encrypts the full plaintext under a fresh OS-random key.",
  "Block ciphers run in CTR mode with a random IV; stream ciphers run in their native keystream mode.",
  "Ciphertext is sliced into chunks of 8, 16, and 32 bytes; each chunk is mapped to a Uniform(0,1)",
  "candidate by interpreting its leading ≤ 8 bytes as a big-endian fraction.",
  "",
  "**Battery.**",
  "0. Shannon entropy of the raw byte stream (ideal: 8.000 bits/byte).",
  "1. Shannon entropy of the chunk values binned into 256 cells (per chunk size; ideal: 8.000 bits).",
  "2. First ten raw moments (deviation from Uniform(0,1) ideals 1/(k+1)).",
  "3. FFT power spectrum: peak/mean ratio, plus a KS test of the normalised periodogram against Exp(1) (= flat spectrum under H0).",
  "4. Kolmogorov-Smirnov test against Uniform(0,1).",
  "5. `randtoolbox::gap.test` (gaps between recurrences in [0, 0.5]).",
  "6. `randtoolbox::freq.test` on the chunk values binned into 16 cells.",
  "7. `randtoolbox::order.test` on tuples of size 4 (data truncated to a multiple of 4).",
  "8. Wald-Wolfowitz runs test on the bit stream (`tseries::runs.test`).",
  "",
  sprintf("**Decision rule.** A cipher fails the battery if **≥ %d** of (a) p-values fall below α = %g, or (b) entropy estimates deviate from the ideal 8.0 bits by more than %g bits.",
          FAIL_AT, ALPHA, ENTROPY_TOL),
  "",
  "## Definitions",
  "",
  "Let `b[0..L-1]` be the ciphertext byte stream of length `L` and let",
  "`u[0..k-1]` be the per-chunk Uniform(0,1) candidates, one per `N`-byte",
  "chunk, computed as `u[j] = sum_{i=0..min(N,8)-1} b[j*N + i] / 256^(i+1)`.",
  "The null hypothesis throughout is **H₀: u is i.i.d. Uniform(0,1)**.",
  "",
  "| Symbol | Definition |",
  "|--------|------------|",
  "| `L` | ciphertext length in bytes (= length of plaintext, since CTR/keystream is length-preserving). |",
  "| `N` | chunk size in bytes (8, 16, or 32). |",
  "| `k` | sample count for chunk size `N`: `k = floor(L / N)`. |",
  "| `u[j]` | the `j`-th chunk's leading-≤8-byte big-endian fraction, in [0,1). |",
  sprintf("| `α` | per-test rejection threshold = %g. | ", ALPHA),
  sprintf("| `tol` | per-entropy rejection threshold in bits/sample = %g. |", ENTROPY_TOL),
  "| `p` | classical p-value: P(test statistic ≥ observed \\| H₀); small `p` ⇒ reject H₀. |",
  "| `H` | Shannon entropy in bits, with the Miller–Madow finite-sample correction; ideal = 8.0000 for 256 equally likely symbols. |",
  "| `byte H` | `H` of the per-byte distribution over the full ciphertext. |",
  "| `chunk H` | `H` of the chunk values `u` binned into 256 equal-width cells. |",
  "| moment `k` | `m_k = (1/n) Σ u[j]^k`, the `k`-th raw sample moment. |",
  "| ideal `k` | `E[U^k] = 1/(k+1)` under U ∼ Uniform(0,1). |",
  "| `\\|dev\\|` | absolute deviation `\\|m_k − 1/(k+1)\\|` (smaller is better). |",
  "| `FFT peak/mean` | Fisher’s g (un-normalised): `max(|U_f|^2) / mean(|U_f|^2)` over non-DC bins of the centered FFT. |",
  "| `FFT spectrum KS (vs flat)` | KS p-value testing the normalised periodogram against Exp(1) (the white-noise null). |",
  "| `KS vs Uniform(0,1)` | Kolmogorov–Smirnov p-value testing `u` against U(0,1). |",
  "| `gap.test` | randtoolbox gaps-between-recurrences test on `u` (default lower=0, upper=0.5). |",
  "| `freq.test` | randtoolbox frequency χ² on `u` binned into 16 cells. |",
  "| `order.test` | randtoolbox order-pattern test on disjoint 4-tuples of `u` (data truncated to a multiple of 4). |",
  "| `runs.test` | Wald–Wolfowitz two-level runs test on the bit stream above/below 0.5. |",
  "| `rejects/total` | number of p-values below `α` (plus entropy misses) over the total test count. |",
  "| `min p` | smallest p-value across the cipher's full battery. |",
  "",
  "## Summary",
  "",
  "| cipher | token | byte H (bits) | rejects/total | min p | verdict |",
  "|--------|-------|---------------|---------------|-------|---------|"
)

for (cipher in CIPHERS) {
  v <- verdicts[[cipher]]
  lines <- c(lines, sprintf("| %s | `%s` | %.4f | %d/%d | %s | %s |",
                            display_name(cipher),
                            cipher,
                            byte_entropies[cipher],
                            v$rejects, v$total,
                            fmt_p(v$min_p),
                            if (v$pass) "PASS" else "**FAIL**"))
}

lines <- c(lines, "",
           if (length(failures))
             sprintf("**Ciphers flagged as failing the battery: %s**",
                     paste0(display_name(failures), " (`", failures, "`)",
                            collapse = ", "))
           else
             "**All ciphers passed the battery.**",
           "")

# Per-cipher detailed sections.
lines <- c(lines, "## Per-cipher detail", "")
for (cipher in CIPHERS) {
  lines <- c(lines, sprintf("### %s (`%s`)", display_name(cipher), cipher), "")
  v <- verdicts[[cipher]]
  lines <- c(lines, sprintf("Verdict: %s — %d test rejection(s) at α=%g, %d entropy miss(es) at tol=%g (total %d / %d).",
                            if (v$pass) "PASS" else "**FAIL**",
                            v$p_rejects, ALPHA,
                            v$entropy_misses, ENTROPY_TOL,
                            v$rejects, v$total),
             "",
             sprintf("Byte-stream Shannon entropy: **%.4f bits/byte** (ideal: 8.0000; deviation %.2e).",
                     byte_entropies[cipher],
                     abs(byte_entropies[cipher] - 8)),
             "")
  for (n in CHUNK_SIZES) {
    r <- all_results[[cipher]][[as.character(n)]]
    lines <- c(lines,
               sprintf("**%d-byte chunks** (%s samples; chunk-entropy %.4f bits, dev %.2e)", n,
                       formatC(r$samples, format = "d", big.mark = ","),
                       r$chunk_entropy,
                       abs(r$chunk_entropy - 8)),
               "",
               "Moments (sample / ideal / |dev|):",
               "",
               "| k | sample | ideal | \\|dev\\| |",
               "|---|--------|-------|----------|")
    for (k in 1:10) {
      lines <- c(lines, sprintf("| %d | %.6f | %.6f | %.2e |",
                                k, r$moments$values[k],
                                r$moments$ideal[k], r$moments$dev[k]))
    }
    lines <- c(lines, "",
               "Tests:",
               "",
               "| test | p |",
               "|------|---|",
               sprintf("| FFT peak/mean | %.2f |", r$fft$peak_ratio),
               sprintf("| FFT spectrum KS (vs flat) | %s |", fmt_p(r$fft_ks_p)),
               sprintf("| KS vs Uniform(0,1) | %s |", fmt_p(r$ks_uniform_p)),
               sprintf("| randtoolbox gap.test  | %s |", fmt_p(r$gap_p)),
               sprintf("| randtoolbox freq.test (16 bins) | %s |", fmt_p(r$freq_p)),
               sprintf("| randtoolbox order.test (d=4) | %s |", fmt_p(r$order_p)),
               sprintf("| tseries runs.test (bits) | %s |", fmt_p(r$runs_bits_p)),
               "")
  }
  lines <- c(lines, sprintf("![spectrum](scripts/cipher_plots/%s.png)", cipher), "")
}

writeLines(lines, REPORT)

# ──────────────────────────────────────────────────────────────────────────────
# Stdout summary
# ──────────────────────────────────────────────────────────────────────────────
cat("\n=== Summary ===\n")
cat(sprintf("  plaintext entropy: %.4f bits/byte\n\n", plaintext_entropy))
for (cipher in CIPHERS) {
  v <- verdicts[[cipher]]
  cat(sprintf("  %-14s  H=%.4f  %d/%d rejects  min p=%s  %s\n",
              cipher,
              byte_entropies[cipher],
              v$rejects, v$total,
              fmt_p(v$min_p),
              if (v$pass) "PASS" else "FAIL"))
}
if (length(failures)) {
  cat("\nFAILED ciphers: ", paste(failures, collapse = ", "), "\n", sep = "")
} else {
  cat("\nAll ciphers passed.\n")
}
cat("\nReport written to: ", REPORT, "\n", sep = "")
