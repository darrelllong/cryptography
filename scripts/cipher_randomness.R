#!/usr/bin/env Rscript
# Randomness battery for the symmetric ciphers in this crate, and the null
# calibration that tells us what the battery's rejection rates really are.
#
# Two modes:
#
#   Rscript scripts/cipher_randomness.R
#       Builds target/release/cipher_encrypt, encrypts the Complete Works of
#       Shakespeare under every cipher (block ciphers in CTR mode with a fresh
#       OS-random key and IV; stream ciphers in their native keystream mode),
#       runs the battery on each ciphertext, and writes R-REPORT.md with the
#       experiment's identity: the source commits and uncommitted-change
#       digests of this crate and rump, the compiler, and the SHA-256 of the
#       executable, the plaintext, this script and every ciphertext.  A
#       ciphertext kept under scripts/cipher_outputs/ is reused only when its
#       manifest names the same executable and plaintext and its bytes still
#       match; an analysis is reused only for the same ciphertext, script and
#       battery version.  When scripts/null_calibration/pvalues.csv exists,
#       the report also carries the calibration section.  Exit status: 0 when
#       every cipher passes, 1 when some cipher fails the battery, 2 when some
#       cipher could not be measured (its verdict is "invalid", with the
#       reason).
#
#   Rscript scripts/cipher_randomness.R --self-test
#       Checks the verdict, the cache acceptance rules and the atomic writer
#       against fixed cases; needs neither cargo nor the plaintext.
#
#   Rscript scripts/cipher_randomness.R --calibrate N [--cores C] [--bytes L]
#       Runs the same battery on N streams of L bytes read from /dev/urandom
#       (the null hypothesis made flesh: no cipher of ours is involved) across
#       C forked workers, appending one row per stream to
#       scripts/null_calibration/pvalues.csv.  Batches are appended as they
#       finish, so an interrupted campaign keeps what it measured.  The
#       record kept in the repository is that file gzipped
#       (scripts/null_calibration/pvalues.csv.gz); the reader takes both.
#
#   Rscript scripts/cipher_randomness.R --calibration-report
#       Rewrites only the calibration section of R-REPORT.md from the CSV.
#
#   Rscript scripts/cipher_randomness.R --calibrate N --held-out [--cores C]
#       Runs the held-out validation campaign of HELD_OUT_PROTOCOL: fresh null
#       streams, written to scripts/null_calibration/held_out-<host>.csv with
#       this script's SHA-256 in every row, and never used to tune anything.
#
#   Rscript scripts/cipher_randomness.R --held-out-report
#       Applies HELD_OUT_PROTOCOL's predeclared decision to the held-out rows
#       and writes that section of R-REPORT.md.
#
# The battery works on the byte stream b_0..b_{L-1}, on its bit stream, and on
# the sequence u_j of 8-byte chunks read as big-endian fractions in [0,1)
# (a double keeps the top 53 bits).  It has m = 7 tests, each with a
# null distribution that needs nothing fitted from the data; the one tuning
# knob, the gap test's tail-pooling threshold, was set by the null
# calibration described at GAP_MIN_EXPECTED and holds for streams of the
# plaintext's length (the pooling depth depends on the stream length, so the
# calibration is read for that length only):
#
#   1. byte-frequency chi-square over 256 cells of all L bytes (Knuth, TAOCP
#      Vol. 2, 3rd ed., section 3.3.2 A);
#   2. Kolmogorov-Smirnov test of u against Uniform(0,1);
#   3. serial test on disjoint pairs (u_{2j}, u_{2j+1}) in 16 x 16 cells
#      (Knuth 3.3.2 B);
#   4. gap test on [0, 1/2), tail pooled at an expected count of 50 (Knuth
#      3.3.2 D, Algorithm G);
#   5. permutation test on disjoint 4-tuples, 24 orderings (Knuth 3.3.2 F);
#   6. Bartlett's cumulative periodogram test for a flat spectrum of u
#      (Bartlett 1955; Durbin 1969);
#   7. Wald-Wolfowitz runs test on the full bit stream.
#
# A cipher fails when any p-value falls below ALPHA / m (Bonferroni). That
# bounds the probability that a good cipher fails by ALPHA, under any
# dependence among the tests, only when every p-value is valid under the null
# (Pr(p <= t) <= t); several tests take p-values from asymptotic laws, so
# ALPHA is nominal and the --calibrate campaign measures the rate attained.  Shannon entropy,
# the first ten moments and Fisher's g of the spectrum are reported as
# descriptions, not counted as tests: the plug-in entropy deficit is, to
# second order, the byte chi-square statistic scaled by 1 / (2 L ln 2), so
# test 1 already is the calibrated form of the entropy check.
#
# Only base R and its `parallel` and `stats` packages are used.

suppressPackageStartupMessages({
  library(parallel)
})

# Resolve paths relative to this script so the workflow runs from any working
# directory and on any user account.  CRYPTOGRAPHY_ROOT overrides.
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
CAL_DIR    <- file.path(SCRIPT_DIR, "null_calibration")
CAL_CSV    <- file.path(CAL_DIR, "pvalues.csv")
CAL_CSV_GZ <- file.path(CAL_DIR, "pvalues.csv.gz")
PT_PATH    <- file.path(SCRIPT_DIR, "shakespeare.txt")
REPORT     <- file.path(ROOT, "R-REPORT.md")

PG_URL      <- "https://www.gutenberg.org/cache/epub/100/pg100.txt"
PG_BYTES    <- 5638480L  # size of Project Gutenberg #100 as fetched
ALPHA       <- 0.001     # nominal family-wise error rate per cipher
CHUNK       <- 8L        # bytes per Uniform(0,1) sample
NULL_SOURCE <- "/dev/urandom"

# Cached analyses (cipher_outputs/*.results.rds) record the battery version
# that produced them; any other version is recomputed from the kept
# ciphertext.
BATTERY_VERSION <- 4L

TESTS <- c(
  byte_chisq  = "byte frequency $\\chi^2$ (256 cells)",
  ks          = "KS vs Uniform(0,1)",
  serial      = "serial test (pairs, $16 \\times 16$ cells)",
  gap         = "gap test (Knuth, $[0, 1/2)$)",
  permutation = "permutation test ($d = 4$)",
  bartlett    = "cumulative periodogram (Bartlett)",
  runs        = "runs test (bit stream)"
)
M_TESTS    <- length(TESTS)
ALPHA_BONF <- ALPHA / M_TESTS

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

# Internal cipher tokens (passed to cipher_encrypt) -> the names the report
# shows, spelled as the algorithms' authors spell them.
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

# ──────────────────────────────────────────────────────────────────────────────
# Command line
# ──────────────────────────────────────────────────────────────────────────────
parse_args <- function(argv) {
  opts <- list(mode = "battery", n = 0L, cores = max(1L, detectCores() - 1L),
               bytes = PG_BYTES, held_out = FALSE)
  i <- 1L
  while (i <= length(argv)) {
    a <- argv[i]
    value <- function() {
      if (i + 1L > length(argv)) stop("missing value after ", a)
      argv[i + 1L]
    }
    if (a == "--calibrate") {
      opts$mode <- "calibrate"; opts$n <- as.integer(value()); i <- i + 2L
    } else if (a == "--cores") {
      opts$cores <- as.integer(value()); i <- i + 2L
    } else if (a == "--bytes") {
      opts$bytes <- as.integer(value()); i <- i + 2L
    } else if (a == "--calibration-report") {
      opts$mode <- "calibration-report"; i <- i + 1L
    } else if (a == "--held-out") {
      opts$held_out <- TRUE; i <- i + 1L
    } else if (a == "--held-out-report") {
      opts$mode <- "held-out-report"; i <- i + 1L
    } else if (a == "--self-test") {
      opts$mode <- "self-test"; i <- i + 1L
    } else {
      stop("unknown argument: ", a)
    }
  }
  if (opts$mode == "calibrate" && (is.na(opts$n) || opts$n < 1L))
    stop("--calibrate needs a positive stream count")
  opts
}
OPTS <- parse_args(commandArgs(trailingOnly = TRUE))

# ──────────────────────────────────────────────────────────────────────────────
# Inputs
# ──────────────────────────────────────────────────────────────────────────────
fetch_shakespeare <- function() {
  if (!file.exists(PT_PATH) || file.info(PT_PATH)$size < 1e6) {
    message("Downloading Shakespeare from Project Gutenberg…")
    utils::download.file(PG_URL, PT_PATH, mode = "wb", quiet = TRUE)
  }
  invisible(NULL)
}

# ──────────────────────────────────────────────────────────────────────────────
# Experiment identity
# ──────────────────────────────────────────────────────────────────────────────

# SHA-256 of a file, by the system tool (sha256sum on Linux, shasum on macOS).
sha256_file <- function(path) {
  tool <- Sys.which("sha256sum")
  out <- if (nzchar(tool)) system2(tool, shQuote(path), stdout = TRUE)
         else system2(Sys.which("shasum"), c("-a", "256", shQuote(path)), stdout = TRUE)
  digest <- sub(" .*", "", out[1])
  if (!grepl("^[0-9a-f]{64}$", digest)) stop("no SHA-256 for ", path)
  digest
}

sha256_text <- function(lines) {
  tmp <- tempfile()
  on.exit(unlink(tmp))
  writeLines(lines, tmp, useBytes = TRUE)
  sha256_file(tmp)
}

# A checkout's commit, and a digest of what differs from it: the tracked diff
# and the names of untracked, unignored files.
git_identity <- function(dir) {
  if (!dir.exists(file.path(dir, ".git")) && !file.exists(file.path(dir, ".git")))
    return(list(commit = "not a git checkout", changes = NA_character_))
  git <- function(...) system2("git", c("-C", shQuote(dir), ...), stdout = TRUE)
  diff <- git("diff", "HEAD", "--binary")
  untracked <- git("ls-files", "--others", "--exclude-standard")
  list(commit = git("rev-parse", "HEAD")[1],
       changes = if (length(diff) || length(untracked))
                   sha256_text(c(diff, "--untracked--", untracked)) else "none")
}

# Build the executable, then name everything the measurement depends on.
build_identity <- function(plaintext_path) {
  rc <- system2("cargo", c("build", "--release", "--bin", "cipher_encrypt",
                           "--manifest-path", shQuote(file.path(ROOT, "Cargo.toml"))))
  if (rc != 0) stop("cargo build of cipher_encrypt failed (rc=", rc, ")")
  list(cryptography = git_identity(ROOT),
       rump = git_identity(file.path(ROOT, "..", "rump")),
       rustc = system2("rustc", "-V", stdout = TRUE)[1],
       features = "default",
       executable_sha256 = sha256_file(BIN),
       plaintext_sha256 = sha256_file(plaintext_path),
       plaintext_bytes = file.info(plaintext_path)$size,
       script_sha256 = sha256_file(script_path),
       battery_version = BATTERY_VERSION)
}

# Write through a temporary file in the same directory and rename, so an
# interrupted write leaves no file under the final name.
write_atomic <- function(path, write) {
  tmp <- tempfile(pattern = paste0(basename(path), ".partial-"), tmpdir = dirname(path))
  on.exit(if (file.exists(tmp)) unlink(tmp))
  write(tmp)
  if (!file.rename(tmp, path)) stop("could not move ", tmp, " to ", path)
  invisible(path)
}

# Whether a kept ciphertext may stand for this experiment: its manifest names
# the same executable and plaintext, and the file still has the recorded
# length and digest.
ciphertext_reusable <- function(manifest, identity, size, digest) {
  !is.null(manifest) &&
    identical(manifest$executable_sha256, identity$executable_sha256) &&
    identical(manifest$plaintext_sha256, identity$plaintext_sha256) &&
    identical(as.numeric(manifest$bytes), as.numeric(identity$plaintext_bytes)) &&
    identical(as.numeric(size), as.numeric(identity$plaintext_bytes)) &&
    identical(manifest$ciphertext_sha256, digest)
}

# Whether a kept analysis may stand: same ciphertext, script and battery.
analysis_reusable <- function(cached, identity, ciphertext_sha256) {
  !is.null(cached) &&
    identical(cached$version, identity$battery_version) &&
    identical(cached$script_sha256, identity$script_sha256) &&
    identical(cached$ciphertext_sha256, ciphertext_sha256)
}

read_rds_or_null <- function(path) {
  if (!file.exists(path)) return(NULL)
  tryCatch(readRDS(path), error = function(e) NULL)
}

# Ciphertext for one cipher, with its manifest: a kept one when
# ciphertext_reusable allows it, otherwise freshly encrypted by the built
# executable and written atomically.
encrypt <- function(name, identity) {
  out <- file.path(OUT_DIR, paste0(name, ".bin"))
  manifest_path <- file.path(OUT_DIR, paste0(name, ".manifest.rds"))
  manifest <- read_rds_or_null(manifest_path)
  if (file.exists(out) &&
      ciphertext_reusable(manifest, identity, file.info(out)$size, sha256_file(out))) {
    manifest$retained <- TRUE
  } else {
    write_atomic(out, function(tmp) {
      rc <- system2(BIN, args = name, stdin = PT_PATH, stdout = tmp)
      if (rc != 0) stop("cipher_encrypt failed for ", name, " (rc=", rc, ")")
      size <- file.info(tmp)$size
      if (!identical(as.numeric(size), as.numeric(identity$plaintext_bytes)))
        stop("cipher_encrypt wrote ", size, " bytes for ", name, ", expected ",
             identity$plaintext_bytes)
    })
    manifest <- list(executable_sha256 = identity$executable_sha256,
                     plaintext_sha256 = identity$plaintext_sha256,
                     bytes = identity$plaintext_bytes,
                     ciphertext_sha256 = sha256_file(out),
                     encrypted = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"),
                     build = identity)
    write_atomic(manifest_path, function(tmp) saveRDS(manifest, tmp))
    manifest$retained <- FALSE
  }
  list(bytes = readBin(out, what = "raw", n = file.info(out)$size), manifest = manifest)
}

# One null stream: L bytes of OS randomness.
null_stream <- function(L) {
  con <- file(NULL_SOURCE, open = "rb", raw = TRUE)
  on.exit(close(con))
  bytes <- readBin(con, what = "raw", n = L)
  if (length(bytes) != L) stop("short read from ", NULL_SOURCE)
  bytes
}

# ──────────────────────────────────────────────────────────────────────────────
# Sample construction
# ──────────────────────────────────────────────────────────────────────────────

# One [0,1) double per CHUNK-byte chunk: the chunk read as a big-endian
# fraction, of which a double keeps the top 53 bits.
to_uniform <- function(bytes) {
  k <- length(bytes) %/% CHUNK
  mat <- matrix(as.integer(bytes[seq_len(k * CHUNK)]), nrow = k, ncol = CHUNK,
                byrow = TRUE)
  out <- numeric(k)
  for (i in seq_len(CHUNK)) out <- out + mat[, i] / (256^i)
  pmin(pmax(out, .Machine$double.eps), 1 - .Machine$double.eps)
}

# Per-byte tables: population count, and the number of adjacent bit pairs
# inside the byte that differ (the within-byte run boundaries).
BYTE_VALUES <- 0:255
POPCOUNT <- vapply(BYTE_VALUES, function(b)
  sum(bitwAnd(bitwShiftR(b, 0:7), 1L)), integer(1))
INNER_BOUNDARIES <- vapply(BYTE_VALUES, function(b)
  sum(bitwAnd(bitwShiftR(bitwXor(b, bitwShiftR(b, 1L)), 0:6), 1L)), integer(1))

# The largest 5-smooth integer not above n.  The spectral test runs on that
# many leading samples so the FFT costs O(n log n) at every length.
largest_5_smooth <- function(n) {
  best <- 1
  p2 <- 1
  while (p2 <= n) {
    p23 <- p2
    while (p23 <= n) {
      p235 <- p23
      while (p235 <= n) {
        if (p235 > best) best <- p235
        p235 <- p235 * 5
      }
      p23 <- p23 * 3
    }
    p2 <- p2 * 2
  }
  as.integer(best)
}

# ──────────────────────────────────────────────────────────────────────────────
# Tests.  Each returns a p-value in (0, 1].
# ──────────────────────────────────────────────────────────────────────────────

chisq_p <- function(observed, expected) {
  stats::pchisq(sum((observed - expected)^2 / expected),
                df = length(observed) - 1L, lower.tail = FALSE)
}

# 1. Byte frequency (Knuth 3.3.2 A on the 256 byte values).
byte_counts <- function(bytes) tabulate(as.integer(bytes) + 1L, nbins = 256L)
byte_chisq_p <- function(counts) chisq_p(counts, rep(sum(counts) / 256, 256))

# 2. Kolmogorov-Smirnov against Uniform(0,1).
ks_uniform_p <- function(u) {
  suppressWarnings(stats::ks.test(u, "punif"))$p.value
}

# 3. Serial test (Knuth 3.3.2 B): disjoint pairs, each coordinate in 16 cells.
serial_p <- function(u, d = 16L) {
  k2 <- length(u) %/% 2L
  a <- floor(u[2L * seq_len(k2) - 1L] * d)
  b <- floor(u[2L * seq_len(k2)] * d)
  counts <- tabulate(a * d + b + 1L, nbins = d * d)
  chisq_p(counts, rep(k2 / (d * d), d * d))
}

# 4. Gap test (Knuth 3.3.2 D, Algorithm G) for [alpha, beta): a gap of length
# r is r values outside the interval followed by one inside it.  Lengths
# 0..t-1 each get a category and lengths >= t share the last one, with t the
# largest value keeping every expected count at least GAP_MIN_EXPECTED; the
# statistic has t degrees of freedom.  The pooling threshold sets how well the
# chi-square approximation holds in the tail: on 60,000 OS-random streams of
# the plaintext's length the test rejected at alpha = 10^-3 with rate 1.42e-3
# pooled at 5 (t = 16), 1.25e-3 at 20 (t = 14), 9.2e-4 at 50 (t = 12) and
# 8.8e-4 at 100 (t = 11), so the threshold is 50; the calibration section of
# the report gives its rate at the deciding threshold alpha / m as well.
# t depends on the number of gaps, so a stream of another length runs a
# different pooling and needs its own calibration.
GAP_MIN_EXPECTED <- 50

# Held-out validation, fixed before any held-out stream exists.  Battery
# version 4 is frozen, GAP_MIN_EXPECTED included.  HELD_OUT_STREAMS fresh
# streams of PG_BYTES bytes from /dev/urandom, none of them part of the tuning
# rows in pvalues.csv.gz.  At the deciding threshold t = ALPHA / m, a p-value
# is valid there when Pr(p <= t) <= t, so only an excess of rejections breaks
# validity: each test's rejection count is checked by the one-sided exact
# binomial test of rate t, and passes when that test's p-value is at least
# HELD_OUT_LEVEL / m; the battery's count of streams with some p < t is
# checked against rate ALPHA at level HELD_OUT_LEVEL.  Counts and 95%
# Clopper-Pearson intervals are reported whatever the outcome, and a failed
# check is reported as a miscalibration of that test at t, not repaired with
# these rows.
HELD_OUT_STREAMS <- 400000L
HELD_OUT_LEVEL   <- 0.05
gap_p <- function(u, alpha = 0, beta = 0.5) {
  p <- beta - alpha
  hits <- which(u >= alpha & u < beta)
  r <- diff(c(0L, hits)) - 1L
  n <- length(r)
  t <- 0L
  while (n * p * (1 - p)^t >= GAP_MIN_EXPECTED &&
         n * (1 - p)^(t + 1) >= GAP_MIN_EXPECTED) t <- t + 1L
  if (t < 1L) return(NA_real_)
  expected <- n * c(p * (1 - p)^(0:(t - 1)), (1 - p)^t)
  observed <- tabulate(pmin(r, t) + 1L, nbins = t + 1L)
  chisq_p(observed, expected)
}

# 5. Permutation test (Knuth 3.3.2 F): disjoint d-tuples classified by the
# relative order of their elements, d! equiprobable classes.  A tuple's class
# is read off its rank vector; tuples with tied elements (probability about
# k d^2 / 2^54 per stream) are left out.
PERMUTATIONS_4 <- (function() {
  perms <- list()
  for (a in 0:3) for (b in 0:3) for (c in 0:3) for (d in 0:3)
    if (length(unique(c(a, b, c, d))) == 4L) perms[[length(perms) + 1L]] <- c(a, b, c, d)
  vapply(perms, function(p) sum(p * 4^(3:0)) + 1L, numeric(1))
})()
permutation_p <- function(u, d = 4L) {
  k <- length(u) %/% d
  mat <- matrix(u[seq_len(k * d)], nrow = k, ncol = d, byrow = TRUE)
  ranks <- matrix(0L, nrow = k, ncol = d)
  for (i in seq_len(d)) for (j in seq_len(d)) if (i != j)
    ranks[, i] <- ranks[, i] + (mat[, j] < mat[, i])
  index <- as.vector(ranks %*% (d^((d - 1):0))) + 1L
  counts <- tabulate(index, nbins = d^d)[PERMUTATIONS_4]
  chisq_p(counts, rep(sum(counts) / length(counts), length(counts)))
}

# 6. Bartlett's cumulative periodogram test.  With I_j the periodogram of the
# centred series at Fourier frequencies j = 1..q, q = floor((n-1)/2), the
# partial sums C_i = (I_1 + ... + I_i) / (I_1 + ... + I_q), i < q, are under
# white noise distributed as the order statistics of q-1 independent
# Uniform(0,1) values, so a Kolmogorov-Smirnov test applies; the scale of the
# spectrum cancels.  Fisher's g (peak over mean) is returned as a description.
spectrum_summary <- function(u) {
  n <- largest_5_smooth(length(u))
  x <- u[seq_len(n)] - mean(u[seq_len(n)])
  q <- (n - 1L) %/% 2L
  spec <- Mod(stats::fft(x))^2
  spec <- spec[2:(q + 1L)]
  C <- cumsum(spec) / sum(spec)
  list(samples = n,
       peak_ratio = max(spec) / mean(spec),
       p = suppressWarnings(stats::ks.test(C[-q], "punif"))$p.value,
       norm = spec / mean(spec))
}

# 7. Wald-Wolfowitz runs test on the whole bit stream.  A run boundary lies
# between two adjacent differing bits, inside a byte or across two bytes; with
# n_0 zeros and n_1 ones among n bits, the run count R has mean
# 1 + 2 n_0 n_1 / n and variance 2 n_0 n_1 (2 n_0 n_1 - n) / (n^2 (n - 1)),
# and (R - mean) / sd is standard normal for n this large.
runs_p <- function(bytes) {
  b <- as.integer(bytes)
  n <- 8 * length(b)
  n1 <- sum(as.numeric(POPCOUNT[b + 1L]))
  n0 <- n - n1
  if (n0 == 0 || n1 == 0) return(0)
  inner <- sum(as.numeric(INNER_BOUNDARIES[b + 1L]))
  low_bits  <- bitwAnd(b[-length(b)], 1L)
  high_bits <- bitwShiftR(b[-1L], 7L)
  across <- sum(low_bits != high_bits)
  R <- 1 + inner + across
  mu <- 1 + 2 * n0 * n1 / n
  sigma <- sqrt(2 * n0 * n1 * (2 * n0 * n1 - n) / (n^2 * (n - 1)))
  2 * stats::pnorm(-abs((R - mu) / sigma))
}

# ──────────────────────────────────────────────────────────────────────────────
# Descriptions (reported, not counted)
# ──────────────────────────────────────────────────────────────────────────────

# Plug-in Shannon entropy in bits.  It never exceeds log2 of the cell count;
# under a uniform source its expected deficit is (K - 1) / (2 n ln 2).
plugin_entropy <- function(counts) {
  n <- sum(counts)
  p <- counts[counts > 0] / n
  -sum(p * log2(p))
}

moments <- function(u) {
  k <- 10L
  vals <- vapply(1:k, function(j) mean(u^j), numeric(1))
  ideal <- 1 / (1 + 1:k)
  list(values = vals, ideal = ideal, dev = abs(vals - ideal))
}

# ──────────────────────────────────────────────────────────────────────────────
# The battery
# ──────────────────────────────────────────────────────────────────────────────
battery <- function(bytes, keep_spectrum = FALSE) {
  started <- proc.time()[["elapsed"]]
  counts <- byte_counts(bytes)
  u <- to_uniform(bytes)
  spec <- spectrum_summary(u)
  p <- c(byte_chisq  = byte_chisq_p(counts),
         ks          = ks_uniform_p(u),
         serial      = serial_p(u),
         gap         = gap_p(u),
         permutation = permutation_p(u),
         bartlett    = spec$p,
         runs        = runs_p(bytes))
  list(bytes = length(bytes),
       samples = length(u),
       spectrum_samples = spec$samples,
       p = p,
       byte_entropy = plugin_entropy(counts),
       peak_ratio = spec$peak_ratio,
       moments = moments(u),
       spectrum = if (keep_spectrum) spec$norm else NULL,
       elapsed = proc.time()[["elapsed"]] - started)
}

# Why `p` is not a complete measurement, or NULL when it is: exactly the
# M_TESTS names of TESTS, once each, each a finite probability in [0, 1].
invalid_reason <- function(p) {
  if (!is.numeric(p) || !is.null(dim(p))) return("p-values are not a numeric vector")
  if (length(p) == 0L) return("no p-values")
  nm <- names(p)
  if (is.null(nm) || any(is.na(nm) | nm == "")) return("unnamed p-values")
  if (anyDuplicated(nm))
    return(paste("duplicated results:", paste(unique(nm[duplicated(nm)]), collapse = ", ")))
  missing <- setdiff(names(TESTS), nm)
  if (length(missing)) return(paste("missing results:", paste(missing, collapse = ", ")))
  extra <- setdiff(nm, names(TESTS))
  if (length(extra)) return(paste("unexpected results:", paste(extra, collapse = ", ")))
  bad <- nm[!(is.finite(p) & p >= 0 & p <= 1)]
  if (length(bad))
    return(paste("not a probability:", paste(sprintf("%s = %s", bad, format(p[bad])), collapse = ", ")))
  NULL
}

# The decision for one battery: "invalid" (with the reason) for an incomplete
# or broken measurement, which is never a pass; otherwise "pass" when every
# p-value is at least ALPHA_BONF and "fail" when one is below.  `error` is a
# producer's failure message, which makes the measurement invalid.
verdict <- function(p, error = NULL) {
  reason <- if (!is.null(error)) error else invalid_reason(p)
  if (!is.null(reason))
    return(list(status = "invalid", reason = reason, min_p = NA_real_, below_alpha = NA_integer_))
  p <- p[names(TESTS)]
  list(status = if (all(p >= ALPHA_BONF)) "pass" else "fail", reason = NULL,
       min_p = min(p), below_alpha = sum(p < ALPHA))
}

# Run a producer of one battery result; its error becomes the result's
# `error` instead of ending the report.
measure <- function(produce) {
  tryCatch(produce(), error = function(e) list(error = conditionMessage(e)))
}

verdict_label <- function(v) switch(v$status, pass = "PASS", fail = "**FAIL**",
                                     invalid = sprintf("**INVALID** (%s)", v$reason))

# 0 when every verdict passes, 1 when some fails, 2 when some is invalid.
exit_status <- function(verdicts) {
  statuses <- vapply(verdicts, function(v) v$status, character(1))
  if (any(statuses == "invalid")) 2L else if (any(statuses == "fail")) 1L else 0L
}

# ──────────────────────────────────────────────────────────────────────────────
# Formatting
# ──────────────────────────────────────────────────────────────────────────────
fmt_sci_latex <- function(x) {
  # m \times 10^{e}, so KaTeX never sees "1.23e-05" inside $...$.
  if (is.na(x)) return("\\mathrm{NA}")
  if (x == 0)  return("0")
  s <- if (x < 0) "-" else ""
  ax <- abs(x)
  e  <- floor(log10(ax))
  m  <- ax / 10^e
  sprintf("%s%.2f \\times 10^{%d}", s, m, e)
}

fmt_p <- function(p) {
  if (is.na(p))   return("n/a")
  if (p < 1e-12) return("<1e-12")
  if (p < 1e-3)  return(sprintf("%.1e", p))
  sprintf("%.3f", p)
}

fmt_int <- function(n) formatC(n, format = "d", big.mark = ",")

fmt_rate <- function(x, n) {
  ci <- stats::binom.test(x, n)$conf.int
  sprintf("%d / %s = %.2e [%.1e, %.1e]", x, fmt_int(n), x / n, ci[1], ci[2])
}

# ──────────────────────────────────────────────────────────────────────────────
# Calibration campaign
# ──────────────────────────────────────────────────────────────────────────────
run_calibration <- function(n_streams, cores, L, held_out = FALSE) {
  dir.create(CAL_DIR, showWarnings = FALSE, recursive = TRUE)
  host <- Sys.info()[["nodename"]]
  if (held_out && L != PG_BYTES) stop("the held-out protocol fixes the length at ", PG_BYTES)
  out_csv <- if (held_out) file.path(CAL_DIR, sprintf("held_out-%s.csv", sub("\\..*", "", host)))
             else CAL_CSV
  script_digest <- sha256_file(script_path)
  batch_size <- max(cores, 64L)
  done <- 0L
  message(sprintf("calibration: %d streams of %s bytes from %s on %d cores (%s)",
                  n_streams, fmt_int(L), NULL_SOURCE, cores, host))
  while (done < n_streams) {
    this_batch <- min(batch_size, n_streams - done)
    stamp <- format(Sys.time(), "%Y-%m-%dT%H:%M:%S%z", tz = "UTC")
    rows <- mclapply(seq_len(this_batch), function(i) {
      res <- battery(null_stream(L))
      data.frame(battery = BATTERY_VERSION, host = host, started = stamp, bytes = L,
                 script_sha256 = script_digest,
                 as.list(signif(res$p, 6)),
                 byte_entropy = signif(res$byte_entropy, 6),
                 elapsed_s = signif(res$elapsed, 4),
                 stringsAsFactors = FALSE)
    }, mc.cores = cores, mc.preschedule = FALSE)
    # A worker that errored hands back the condition; one the kernel killed
    # hands back NULL.  Either ends the campaign rather than being counted.
    failed <- !vapply(rows, is.data.frame, logical(1))
    if (any(failed)) {
      stop("worker ", which(failed)[1], " of the batch failed: ",
           paste(format(rows[[which(failed)[1]]]), collapse = " "))
    }
    rows <- do.call(rbind, rows)
    reasons <- apply(as.matrix(rows[, names(TESTS)]), 1, function(r) {
      reason <- invalid_reason(setNames(as.numeric(r), names(TESTS)))
      if (is.null(reason)) NA_character_ else reason
    })
    if (any(!is.na(reasons))) stop("a null stream gave an invalid measurement: ",
                                   reasons[!is.na(reasons)][1])
    utils::write.table(rows, out_csv, sep = ",", row.names = FALSE,
                       col.names = !file.exists(out_csv), append = file.exists(out_csv))
    done <- done + nrow(rows)
    message(sprintf("  %s / %s streams (batch mean %.1f s per stream)",
                    fmt_int(done), fmt_int(n_streams), mean(rows$elapsed_s)))
  }
  invisible(NULL)
}

# Rows of the current battery version and of streams of `bytes` bytes only:
# a stream measured by another version of a test, or at another length
# (which changes the gap test's pooling depth), says nothing about this one.
read_calibration <- function(bytes) {
  files <- Filter(file.exists, c(CAL_CSV_GZ, CAL_CSV))
  if (!length(files)) return(NULL)
  cal <- do.call(rbind, lapply(files, utils::read.csv, stringsAsFactors = FALSE))
  cal <- cal[cal$battery == BATTERY_VERSION & cal$bytes == bytes, ]
  if (nrow(cal) == 0) return(NULL)
  pm <- as.matrix(cal[, names(TESTS)])
  if (any(!(is.finite(pm) & pm >= 0 & pm <= 1)))
    stop(sum(!apply(is.finite(pm) & pm >= 0 & pm <= 1, 1, all)),
         " calibration rows hold a value that is not a probability")
  cal
}

calibration_lines <- function(cal) {
  n <- nrow(cal)
  pm <- as.matrix(cal[, names(TESTS)])
  min_p <- apply(pm, 1, min)
  # Batch stamps carry their UTC offset; compare them as instants.
  started <- as.POSIXct(strptime(cal$started, "%Y-%m-%dT%H:%M:%S%z", tz = "UTC"))
  window <- format(range(started, na.rm = TRUE), "%Y-%m-%d %H:%M", tz = "UTC")
  lines <- c(
    "## Calibration on OS-random streams", "",
    sprintf(paste("The battery ran on %s streams of %s bytes each read from `%s`",
                  "(hosts: %s; %s to %s UTC; mean %.1f s per stream).  A stream",
                  "that is random by construction should reject each test with",
                  "probability $\\alpha = %g$ and fail the battery with",
                  "probability at most $\\alpha$ if every p-value is valid; the table gives the observed",
                  "counts with Clopper-Pearson 95%% intervals, and the",
                  "Kolmogorov-Smirnov p-value of each test's %s p-values",
                  "against Uniform(0,1), which is what a calibrated test",
                  "produces under the null."),
            fmt_int(n), fmt_int(cal$bytes[1]), NULL_SOURCE,
            paste(unique(cal$host), collapse = ", "),
            window[1], window[2], mean(cal$elapsed_s),
            ALPHA, fmt_int(n)),
    "",
    sprintf("| test | rejections at $\\alpha = %g$ (rate, 95%% CI) | rejections at $\\alpha / m = %s$ | KS of p-values vs Uniform(0,1) |",
            ALPHA, fmt_sci_latex(ALPHA_BONF)),
    "|------|------|------|------|")
  for (t in names(TESTS)) {
    p <- pm[, t]
    p <- p[!is.na(p)]
    ks <- suppressWarnings(stats::ks.test(p, "punif"))$p.value
    lines <- c(lines, sprintf("| %s | %s | %d | %s |", TESTS[[t]],
                              fmt_rate(sum(p < ALPHA), length(p)),
                              sum(p < ALPHA_BONF), fmt_p(ks)))
  }
  lines <- c(lines, "",
             sprintf("Battery failures (some $p < \\alpha / m$): %s; nominal bound $%g$.",
                     fmt_rate(sum(min_p < ALPHA_BONF), n), ALPHA),
             sprintf("Streams with some $p < \\alpha$: %s; nominal bound $m \\alpha = %g$.",
                     fmt_rate(sum(min_p < ALPHA), n), M_TESTS * ALPHA),
             "",
             "Spearman correlation of the p-values across streams (dependence makes the Bonferroni bound loose, never unsafe, when every p-value is valid):",
             "",
             paste0("| | ", paste(names(TESTS), collapse = " | "), " |"),
             paste0("|---|", paste(rep("---", M_TESTS), collapse = "|"), "|"))
  rho <- stats::cor(pm, method = "spearman", use = "pairwise.complete.obs")
  for (i in seq_len(M_TESTS)) {
    lines <- c(lines, paste0("| ", names(TESTS)[i], " | ",
                             paste(sprintf("%.3f", rho[i, ]), collapse = " | "), " |"))
  }
  lines <- c(lines, "",
             sprintf("Byte entropy over the null streams: mean $8 - H = %s$ bits, sd $%s$ bits; the second-order prediction is mean $(K-1)/(2 L \\ln 2) = %s$ and sd $\\sqrt{2(K-1)}/(2 L \\ln 2) = %s$ with $K = 256$.",
                     fmt_sci_latex(mean(8 - cal$byte_entropy)),
                     fmt_sci_latex(stats::sd(8 - cal$byte_entropy)),
                     fmt_sci_latex(255 / (2 * cal$bytes[1] * log(2))),
                     fmt_sci_latex(sqrt(510) / (2 * cal$bytes[1] * log(2)))),
             "", "![calibration](scripts/cipher_plots/calibration.png)", "")
  png(file.path(PLOT_DIR, "calibration.png"), width = 1400, height = 400, res = 110)
  par(mfrow = c(1, M_TESTS), mar = c(4, 3, 3, 1))
  for (t in names(TESTS)) {
    hist(pm[, t], breaks = 20, main = t, xlab = "p", col = "steelblue", border = "white")
    abline(h = n / 20, col = "red", lty = 2)
  }
  dev.off()
  lines
}

# The predeclared held-out decision (HELD_OUT_PROTOCOL above), applied to the
# held-out rows of the current battery version at PG_BYTES bytes.
held_out_lines <- function() {
  files <- list.files(CAL_DIR, pattern = "^held_out-.*\\.csv(\\.gz)?$", full.names = TRUE)
  if (!length(files)) stop("no held-out rows in ", CAL_DIR)
  rows <- do.call(rbind, lapply(files, utils::read.csv, stringsAsFactors = FALSE))
  rows <- rows[rows$battery == BATTERY_VERSION & rows$bytes == PG_BYTES, ]
  n <- nrow(rows)
  if (n == 0L) stop("no held-out rows of battery ", BATTERY_VERSION, " at ", PG_BYTES, " bytes")
  pm <- as.matrix(rows[, names(TESTS)])
  if (any(!(is.finite(pm) & pm >= 0 & pm <= 1))) stop("held-out rows hold a value that is not a probability")
  excess_p <- function(x, rate) stats::binom.test(x, n, rate, alternative = "greater")$p.value
  lines <- c("## Held-out calibration at the decision threshold", "",
             sprintf(paste("Predeclared before any held-out stream was drawn (the protocol at `HELD_OUT_STREAMS` in",
                           "`scripts/cipher_randomness.R`; scripts `%s`): %s fresh streams of %s bytes from `%s`",
                           "(hosts %s), battery version %d frozen.  At $t = \\alpha / m = %s$ a valid p-value has",
                           "$\\Pr(p \\le t) \\le t$, so each test passes when the one-sided exact binomial test for an",
                           "excess of rejections over rate $t$ gives at least %g / %d, and the battery passes when the",
                           "same test of the streams with some $p < t$ against rate $\\alpha$ gives at least %g."),
                     paste(unique(substr(rows$script_sha256, 1, 16)), collapse = "`, `"),
                     fmt_int(n), fmt_int(PG_BYTES), NULL_SOURCE, paste(unique(rows$host), collapse = ", "),
                     BATTERY_VERSION, fmt_sci_latex(ALPHA_BONF), HELD_OUT_LEVEL, M_TESTS, HELD_OUT_LEVEL),
             if (n < HELD_OUT_STREAMS) c("", sprintf("**Incomplete:** %s of the %s predeclared streams.",
                                                     fmt_int(n), fmt_int(HELD_OUT_STREAMS))),
             "",
             sprintf("| test | rejections at $t$ (rate, 95%% CI) | expected | excess p | verdict |"),
             "|------|------|------|------|------|")
  for (t in names(TESTS)) {
    x <- sum(pm[, t] < ALPHA_BONF)
    ep <- excess_p(x, ALPHA_BONF)
    lines <- c(lines, sprintf("| %s | %s | %.1f | %s | %s |", TESTS[[t]], fmt_rate(x, n),
                              n * ALPHA_BONF, fmt_p(ep),
                              if (ep >= HELD_OUT_LEVEL / M_TESTS) "calibrated" else "**miscalibrated at t**"))
  }
  any_t <- sum(apply(pm, 1, min) < ALPHA_BONF)
  ep <- excess_p(any_t, ALPHA)
  # The smallest count the per-test rule flags, and the rate at which a test
  # reaches it half the time: what "calibrated" can and cannot exclude.
  counts <- 0:ceiling(10 * n * ALPHA_BONF + 50)
  flagged <- counts[which(vapply(counts, function(x) excess_p(x, ALPHA_BONF) < HELD_OUT_LEVEL / M_TESTS,
                                 logical(1)))[1]]
  half_power_rate <- stats::uniroot(function(r) stats::pbinom(flagged - 1L, n, r, lower.tail = FALSE) - 0.5,
                                    c(ALPHA_BONF, 10 * ALPHA_BONF), tol = ALPHA_BONF * 1e-9)$root
  c(lines, "",
    sprintf(paste("At %s streams the per-test rule flags a count of %d or more, so a test whose true rejection",
                  "rate at $t$ is %.2f times $t$ is flagged only half the time: \"calibrated\" excludes",
                  "gross excesses, not small ones."),
            fmt_int(n), flagged, half_power_rate / ALPHA_BONF),
    "",
    sprintf("Battery failures (some $p < t$): %s against rate $\\alpha = %g$ (expected %.1f); excess p %s: %s.",
            fmt_rate(any_t, n), ALPHA, n * ALPHA, fmt_p(ep),
            if (ep >= HELD_OUT_LEVEL) "within the nominal rate" else "**above the nominal rate**"),
    "")
}

# Replace or append a `## ` section of an existing report.
splice_section <- function(report_lines, heading, section_lines) {
  start <- grep(paste0("^", heading), report_lines)
  if (!length(start)) return(c(report_lines, section_lines))
  after <- grep("^## ", report_lines)
  after <- after[after > start[1]]
  end <- if (length(after)) after[1] - 1L else length(report_lines)
  c(report_lines[seq_len(start[1] - 1L)], section_lines,
    if (end < length(report_lines)) report_lines[(end + 1L):length(report_lines)])
}

# Replace or append the calibration section of an existing report.
splice_calibration <- function(report_lines, cal_lines) {
  start <- grep("^## Calibration on OS-random streams", report_lines)
  if (!length(start)) return(c(report_lines, cal_lines))
  after <- grep("^## ", report_lines)
  after <- after[after > start[1]]
  end <- if (length(after)) after[1] - 1L else length(report_lines)
  c(report_lines[seq_len(start[1] - 1L)], cal_lines,
    if (end < length(report_lines)) report_lines[(end + 1L):length(report_lines)])
}

# ──────────────────────────────────────────────────────────────────────────────
# Cipher battery and report
# ──────────────────────────────────────────────────────────────────────────────
make_plot <- function(cipher, norm) {
  png(file.path(PLOT_DIR, paste0(cipher, ".png")), width = 900, height = 300, res = 110)
  on.exit(dev.off())
  par(mar = c(4, 4, 2, 1))
  idx <- seq.int(1, length(norm), length.out = min(2000, length(norm)))
  plot(idx, log10(norm[idx] + 1e-9), type = "l",
       main = sprintf("%s — periodogram of %d-byte chunks", display_name(cipher), CHUNK),
       xlab = "frequency bin", ylab = "log10(power / mean)", col = "steelblue")
  abline(h = 0, col = "red", lty = 2)
}

run_battery <- function() {
  dir.create(OUT_DIR,  showWarnings = FALSE, recursive = TRUE)
  dir.create(PLOT_DIR, showWarnings = FALSE, recursive = TRUE)
  fetch_shakespeare()
  plaintext <- readBin(PT_PATH, what = "raw", n = file.info(PT_PATH)$size)
  plaintext_size <- length(plaintext)
  plaintext_entropy <- plugin_entropy(byte_counts(plaintext))
  identity <- build_identity(PT_PATH)
  k <- plaintext_size %/% CHUNK

  results <- list()
  for (cipher in CIPHERS) {
    cache_path <- file.path(OUT_DIR, paste0(cipher, ".results.rds"))
    res <- measure(function() {
      ct <- encrypt(cipher, identity)
      cached <- read_rds_or_null(cache_path)
      if (analysis_reusable(cached, identity, ct$manifest$ciphertext_sha256)) {
        message(sprintf("[%-14s] %s ciphertext, cached analysis", cipher,
                        if (ct$manifest$retained) "kept" else "new"))
        r <- cached$result
        r$analysed <- cached$analysed
      } else {
        message(sprintf("[%-14s] %s ciphertext, analysing", cipher,
                        if (ct$manifest$retained) "kept" else "new"))
        r <- battery(ct$bytes, keep_spectrum = TRUE)
        r$analysed <- format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")
        write_atomic(cache_path, function(tmp) saveRDS(
          list(version = identity$battery_version, script_sha256 = identity$script_sha256,
               ciphertext_sha256 = ct$manifest$ciphertext_sha256,
               analysed = r$analysed, result = r), tmp))
      }
      r$manifest <- ct$manifest
      make_plot(cipher, r$spectrum)
      r$spectrum <- NULL
      r
    })
    res$verdict <- verdict(res$p, res$error)
    if (!is.null(res$error)) message(sprintf("[%-14s] not measured: %s", cipher, res$error))
    results[[cipher]] <- res
  }
  statuses <- vapply(results, function(r) r$verdict$status, character(1))
  failures <- names(results)[statuses == "fail"]
  invalid <- names(results)[statuses == "invalid"]
  measured <- function(r) r$verdict$status != "invalid"
  cal <- read_calibration(plaintext_size)
  changes <- function(id) if (identical(id$changes, "none")) "none" else sprintf("SHA-256 `%s`", id$changes)

  lines <- c(
    "# Symmetric-Cipher Randomness Report", "",
    sprintf("Rendered %s by `scripts/cipher_randomness.R` (battery version %d).",
            format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), BATTERY_VERSION),
    sprintf("Toolchain: %s, base packages only.", R.version.string),
    "",
    sprintf("**Plaintext.** Project Gutenberg #100 — *The Complete Works of William Shakespeare* (%s bytes; SHA-256 `%s`; byte-entropy %.6f bits/byte).",
            fmt_int(plaintext_size), identity$plaintext_sha256, plaintext_entropy),
    "",
    "**Experiment identity.** Every ciphertext below was produced by the executable and plaintext named here and analysed by this script; the Ciphertexts section gives each one's digest and when it was encrypted and analysed.",
    "",
    "| item | identity |",
    "|------|----------|",
    sprintf("| cryptography | commit `%s`; uncommitted changes: %s |",
            identity$cryptography$commit, changes(identity$cryptography)),
    sprintf("| rump | commit `%s`; uncommitted changes: %s |",
            identity$rump$commit, changes(identity$rump)),
    sprintf("| compiler | %s; features: %s |", identity$rustc, identity$features),
    sprintf("| `cipher_encrypt` | SHA-256 `%s` |", identity$executable_sha256),
    sprintf("| script | SHA-256 `%s` |", identity$script_sha256),
    "",
    "**Caveat.** Passing this battery is **necessary** for a usable symmetric primitive but is **not sufficient** for cryptographic security; the battery rules out gross statistical defects in the keystream, not key-recovery, distinguishing-attack, or related-key resistance.",
    "",
    "**Method.** Each cipher encrypts the full plaintext under a fresh OS-random key.",
    "Block ciphers run in CTR mode with a random IV; stream ciphers run in their native keystream mode.",
    sprintf("The ciphertext is read three ways: as $L$ bytes, as $8L$ bits, and as $k = \\lfloor L / %d \\rfloor$ = %s values $u_j \\in [0, 1)$, one per %d-byte chunk taken as a big-endian fraction (a double keeps the top 53 bits).",
            CHUNK, fmt_int(k), CHUNK),
    "",
    sprintf("**Battery.** $m = %d$ tests, each with a parameter-free null distribution:", M_TESTS),
    "",
    "1. Byte-frequency $\\chi^2$ over the 256 byte values of all $L$ bytes (Knuth, *TAOCP* Vol. 2, §3.3.2 A).",
    "2. Kolmogorov-Smirnov test of $u$ against Uniform(0,1).",
    "3. Serial test on disjoint pairs $(u_{2j}, u_{2j+1})$ in $16 \\times 16$ cells (Knuth §3.3.2 B).",
    sprintf("4. Gap test on $[0, 1/2)$ with the tail pooled so every expected count is at least %d (Knuth §3.3.2 D).", GAP_MIN_EXPECTED),
    "5. Permutation test on disjoint 4-tuples, 24 orderings (Knuth §3.3.2 F).",
    sprintf("6. Bartlett's cumulative periodogram test for a flat spectrum, on the leading %s values of $u$ (the largest 5-smooth length, so the FFT is $O(n \\log n)$).",
            fmt_int(largest_5_smooth(plaintext_size %/% CHUNK))),
    "7. Wald-Wolfowitz runs test on the full bit stream.",
    "",
    sprintf("**Decision rule.** A cipher fails when any of its $m = %d$ p-values falls below $\\alpha / m = %s$ (Bonferroni).  That bounds the probability that a good cipher fails by $\\alpha = %g$ under any dependence among the tests only if every p-value is valid under the null, $\\Pr(p \\le t) \\le t$; several tests take their p-values from asymptotic laws, so $\\alpha$ is a nominal rate, and the calibration section reports the rates the battery attains on streams that are random by construction.  The `p < α` column counts the p-values below $\\alpha$, which a good cipher shows at a rate of about $m \\alpha = %g$ per battery.  A pass means only that these statistics did not detect a departure from independent uniform bytes; it is not evidence of key secrecy, authentication security or unpredictability.",
            M_TESTS, fmt_sci_latex(ALPHA_BONF), ALPHA, M_TESTS * ALPHA),
    "",
    sprintf("**Entropy.** The plug-in byte entropy $H$ never exceeds $8$ bits; to second order $8 - H = \\chi^2 / (2 L \\ln 2)$ with $\\chi^2$ the byte-frequency statistic, so under a uniform source $8 - H$ has mean $(K - 1) / (2 L \\ln 2) = %s$ bits and standard deviation $\\sqrt{2 (K - 1)} / (2 L \\ln 2) = %s$ bits ($K = 256$, $L =$ %s).  Test 1 is therefore the calibrated form of the entropy check; $H$ is printed to six decimals as a description.",
            fmt_sci_latex(255 / (2 * plaintext_size * log(2))),
            fmt_sci_latex(sqrt(510) / (2 * plaintext_size * log(2))),
            fmt_int(plaintext_size)),
    "",
    "## Definitions", "",
    "Let $b_0, b_1, \\ldots, b_{L-1}$ be the ciphertext bytes and",
    sprintf("$u_j = \\sum_{i=0}^{%d} b_{%dj+i} \\, 256^{-(i+1)}$ the chunk values; under $H_0$ the $u_j$ are independent Uniform(0,1).",
            CHUNK - 1L, CHUNK),
    "",
    "| Symbol | Definition |",
    "|--------|------------|",
    "| $L$ | ciphertext length in bytes (equal to the plaintext length; CTR and keystream modes preserve length). |",
    sprintf("| $k$ | number of chunk values, $\\lfloor L / %d \\rfloor$. |", CHUNK),
    sprintf("| $\\alpha = %g$ | nominal family-wise error rate per cipher; each test rejects at $\\alpha / m = %s$. |", ALPHA, fmt_sci_latex(ALPHA_BONF)),
    "| $p$ | classical p-value $\\Pr(T \\ge T_\\mathrm{obs} \\mid H_0)$; small $p$ rejects $H_0$. |",
    "| $H$ | plug-in Shannon entropy of the byte distribution, in bits. |",
    "| $m_k$ | the $k$-th raw sample moment of $u$; ideal $E[U^k] = 1/(k+1)$. |",
    "| Fisher's $g$ | peak over mean of the periodogram at the non-zero Fourier frequencies. |",
    sprintf("| `byte χ²` | %s: $\\sum_v (c_v - L/256)^2 / (L/256)$ on the byte counts $c_v$, 255 degrees of freedom. |", TESTS[["byte_chisq"]]),
    "| `KS` | Kolmogorov-Smirnov distance between the empirical distribution of $u$ and Uniform(0,1). |",
    "| `serial` | $\\chi^2$ with 255 degrees of freedom on the $16 \\times 16$ cell counts of the pairs $(\\lfloor 16 u_{2j} \\rfloor, \\lfloor 16 u_{2j+1} \\rfloor)$. |",
    sprintf("| `gap` | gap lengths for $u \\in [0, 1/2)$, lengths $0, \\ldots, t-1$ separate and $\\ge t$ pooled with every expected count at least %d, $\\chi^2$ with $t$ degrees of freedom. |", GAP_MIN_EXPECTED),
    "| `permutation` | $\\chi^2$ with 23 degrees of freedom on the 24 orderings of the disjoint 4-tuples of $u$. |",
    "| `Bartlett` | with $I_j$ the periodogram at Fourier frequency $j$ and $q = \\lfloor (n-1)/2 \\rfloor$, the KS distance of $C_i = \\sum_{j \\le i} I_j / \\sum_{j \\le q} I_j$, $i < q$, from Uniform(0,1). |",
    "| `runs` | number of runs in the $8L$-bit stream against its Wald-Wolfowitz mean and variance, two-sided normal. |",
    "| `p < α` | number of the $m$ p-values below $\\alpha$. |",
    "| `min p` | smallest of the $m$ p-values. |",
    "",
    if (is.null(cal))
      c(sprintf("**Calibration.** No null calibration of battery version %d exists for streams of %s bytes, so the rates this battery attains at that length are unmeasured.",
                BATTERY_VERSION, fmt_int(plaintext_size)), ""),
    "## Summary", "",
    "| cipher | token | $H$ (bits) | $8 - H$ (bits) | Fisher's $g$ | `p < α` | min p | verdict |",
    "|--------|-------|------------|----------------|--------------|---------|-------|---------|")
  for (cipher in CIPHERS) {
    r <- results[[cipher]]
    lines <- c(lines, if (measured(r))
      sprintf("| %s | `%s` | %.6f | $%s$ | %.1f | %d | %s | %s |",
              display_name(cipher), cipher, r$byte_entropy,
              fmt_sci_latex(8 - r$byte_entropy), r$peak_ratio,
              r$verdict$below_alpha, fmt_p(r$verdict$min_p), verdict_label(r$verdict))
    else
      sprintf("| %s | `%s` | n/a | n/a | n/a | n/a | n/a | %s |",
              display_name(cipher), cipher, verdict_label(r$verdict)))
  }
  lines <- c(lines, "",
             if (length(failures))
               sprintf("**Ciphers failing the battery: %s**",
                       paste0(display_name(failures), " (`", failures, "`)", collapse = ", ")),
             if (length(invalid))
               sprintf("**Ciphers not measured (invalid): %s**",
                       paste0(display_name(invalid), " (`", invalid, "`)", collapse = ", ")),
             if (!length(failures) && !length(invalid))
               sprintf("**All %d ciphers pass the battery.**", length(CIPHERS)),
             "",
             "## Ciphertexts", "",
             "| cipher | ciphertext SHA-256 | bytes | encrypted | analysed |",
             "|--------|--------------------|-------|-----------|----------|")
  for (cipher in CIPHERS) {
    r <- results[[cipher]]
    lines <- c(lines, if (measured(r))
      sprintf("| %s | `%s` | %s | %s | %s |", display_name(cipher),
              r$manifest$ciphertext_sha256, fmt_int(r$manifest$bytes),
              r$manifest$encrypted, r$analysed)
    else sprintf("| %s | n/a | n/a | n/a | n/a |", display_name(cipher)))
  }
  lines <- c(lines, "", "## Per-cipher detail", "")
  for (cipher in CIPHERS) {
    r <- results[[cipher]]
    lines <- c(lines, sprintf("### %s (`%s`)", display_name(cipher), cipher), "")
    if (!measured(r)) {
      lines <- c(lines, sprintf("Verdict: %s.", verdict_label(r$verdict)), "")
      next
    }
    lines <- c(lines,
               sprintf("Verdict: %s &mdash; min p = %s against $\\alpha / m = %s$; %d of %d p-values below $\\alpha = %g$.",
                       verdict_label(r$verdict),
                       fmt_p(r$verdict$min_p), fmt_sci_latex(ALPHA_BONF),
                       r$verdict$below_alpha, M_TESTS, ALPHA),
               "",
               sprintf("Byte entropy $H = %.6f$ bits ($8 - H = %s$); %s chunk values; Fisher's $g = %.2f$.",
                       r$byte_entropy, fmt_sci_latex(8 - r$byte_entropy),
                       fmt_int(r$samples), r$peak_ratio),
               "",
               "| test | p |", "|------|---|")
    for (t in names(TESTS)) {
      lines <- c(lines, sprintf("| %s | %s |", TESTS[[t]], fmt_p(r$p[[t]])))
    }
    lines <- c(lines, "", "Moments of $u$ (sample, ideal, deviation):", "",
               "| $k$ | $m_k$ | $1/(k+1)$ | dev |", "|-----|-------|-----------|-----|")
    for (j in 1:10) {
      lines <- c(lines, sprintf("| %d | %.6f | %.6f | %.2e |", j,
                                r$moments$values[j], r$moments$ideal[j], r$moments$dev[j]))
    }
    lines <- c(lines, "", sprintf("![spectrum](scripts/cipher_plots/%s.png)", cipher), "")
  }

  if (!is.null(cal)) lines <- c(lines, calibration_lines(cal))
  write_atomic(REPORT, function(tmp) writeLines(lines, tmp))

  cat("\n=== Summary ===\n")
  cat(sprintf("  plaintext entropy: %.4f bits/byte\n\n", plaintext_entropy))
  for (cipher in CIPHERS) {
    r <- results[[cipher]]
    if (measured(r)) {
      cat(sprintf("  %-14s  H=%.6f  p<alpha: %d  min p=%s  %s\n", cipher, r$byte_entropy,
                  r$verdict$below_alpha, fmt_p(r$verdict$min_p), toupper(r$verdict$status)))
    } else {
      cat(sprintf("  %-14s  INVALID: %s\n", cipher, r$verdict$reason))
    }
  }
  cat("\n")
  if (length(failures)) cat("FAILING:", paste(failures, collapse = ", "), "\n")
  if (length(invalid)) cat("NOT MEASURED:", paste(invalid, collapse = ", "), "\n")
  if (!length(failures) && !length(invalid)) cat("All ciphers pass.\n")
  cat(sprintf("Report written to %s\n", REPORT))
  exit_status(lapply(results, function(r) r$verdict))
}

# ──────────────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────────────
# Fixed cases for the decision, the exit status, the cache rules and the
# atomic writer; returns 0 when every case holds and 1 otherwise.
self_test <- function() {
  failures <- 0L
  check <- function(label, ok) {
    cat(sprintf("%-64s %s\n", label, if (isTRUE(ok)) "ok" else "FAILED"))
    if (!isTRUE(ok)) failures <<- failures + 1L
  }
  named <- function(values) setNames(values, names(TESTS))
  status <- function(p, error = NULL) verdict(p, error)$status
  half <- rep(0.5, M_TESTS - 1L)

  check("all p = 0.5 passes", status(named(rep(0.5, M_TESTS))) == "pass")
  check("exact 0 is a probability, and fails", status(named(c(0, half))) == "fail")
  check("exact 1 is a probability, and passes", status(named(rep(1, M_TESTS))) == "pass")
  check("p = alpha / m passes", status(named(rep(ALPHA_BONF, M_TESTS))) == "pass")
  check("p just below alpha / m fails", status(named(c(ALPHA_BONF * (1 - 1e-9), half))) == "fail")
  check("no results is invalid", status(numeric(0)) == "invalid")
  check("NULL is invalid", status(NULL) == "invalid")
  check("seven NA is invalid", status(named(rep(NA_real_, M_TESTS))) == "invalid")
  check("one 0.5 and six NA is invalid", status(named(c(0.5, rep(NA_real_, M_TESTS - 1L)))) == "invalid")
  check("a missing result is invalid", status(named(rep(0.5, M_TESTS))[-3]) == "invalid")
  for (bad in list(NaN, Inf, -Inf, 2, 1.25, -0.5)) {
    check(sprintf("a p-value of %s is invalid", format(bad)), status(named(c(bad, half))) == "invalid")
  }
  check("seven values of 2 are invalid", status(named(rep(2, M_TESTS))) == "invalid")
  dup <- named(rep(0.5, M_TESTS))
  names(dup)[2] <- names(dup)[1]
  check("a duplicated name in place of another is invalid", status(dup) == "invalid")
  check("an extra duplicated result is invalid",
        status(c(named(rep(0.5, M_TESTS)), ks = 0.5)) == "invalid")
  check("unnamed values are invalid", status(rep(0.5, M_TESTS)) == "invalid")
  extra <- named(rep(0.5, M_TESTS))
  names(extra)[M_TESTS] <- "other"
  check("an unexpected name is invalid", status(extra) == "invalid")
  check("character values are invalid", status(setNames(rep("0.5", M_TESTS), names(TESTS))) == "invalid")
  failed <- measure(function() stop("producer failed"))
  check("a producer that errors is invalid, with its message",
        status(failed$p, failed$error) == "invalid" &&
          grepl("producer failed", verdict(failed$p, failed$error)$reason))
  check("an error alongside complete p-values is invalid",
        status(named(rep(0.5, M_TESTS)), "analysis failed after the tests") == "invalid")
  v <- function(st) list(status = st)
  check("exit status 0 when every cipher passes", exit_status(list(v("pass"), v("pass"))) == 0L)
  check("exit status 1 when one fails", exit_status(list(v("pass"), v("fail"))) == 1L)
  check("exit status 2 when one is invalid", exit_status(list(v("fail"), v("invalid"))) == 2L)

  digest <- function(ch) strrep(ch, 64)
  identity <- list(executable_sha256 = digest("a"), plaintext_sha256 = digest("b"),
                   plaintext_bytes = 100, script_sha256 = digest("c"),
                   battery_version = BATTERY_VERSION)
  manifest <- list(executable_sha256 = digest("a"), plaintext_sha256 = digest("b"),
                   bytes = 100, ciphertext_sha256 = digest("d"))
  check("a kept ciphertext of the same executable and plaintext is reused",
        ciphertext_reusable(manifest, identity, 100, digest("d")))
  check("a ciphertext without a manifest is not reused",
        !ciphertext_reusable(NULL, identity, 100, digest("d")))
  check("a ciphertext of another executable is not reused",
        !ciphertext_reusable(modifyList(manifest, list(executable_sha256 = digest("e"))),
                             identity, 100, digest("d")))
  check("a ciphertext of another plaintext is not reused",
        !ciphertext_reusable(manifest, modifyList(identity, list(plaintext_sha256 = digest("e"))),
                             100, digest("d")))
  check("a truncated ciphertext is not reused",
        !ciphertext_reusable(manifest, identity, 99, digest("d")))
  check("an altered ciphertext is not reused",
        !ciphertext_reusable(manifest, identity, 100, digest("e")))
  cached <- list(version = BATTERY_VERSION, script_sha256 = digest("c"),
                 ciphertext_sha256 = digest("d"))
  check("an analysis of the same ciphertext and script is reused",
        analysis_reusable(cached, identity, digest("d")))
  check("an analysis by another script is not reused",
        !analysis_reusable(cached, modifyList(identity, list(script_sha256 = digest("e"))),
                           digest("d")))
  check("an analysis of another ciphertext is not reused",
        !analysis_reusable(cached, identity, digest("e")))
  check("an analysis by another battery version is not reused",
        !analysis_reusable(modifyList(cached, list(version = BATTERY_VERSION - 1L)),
                           identity, digest("d")))

  dir <- tempfile("atomic-")
  dir.create(dir)
  target <- file.path(dir, "out.bin")
  write_atomic(target, function(tmp) writeBin(as.raw(1:10), tmp))
  check("an atomic write leaves the file and no partial",
        identical(list.files(dir), "out.bin"))
  interrupted <- tryCatch(write_atomic(target, function(tmp) {
    writeBin(as.raw(1:3), tmp)
    stop("interrupted")
  }), error = function(e) "stopped")
  check("an interrupted write keeps the old file and removes the partial",
        identical(interrupted, "stopped") && identical(list.files(dir), "out.bin") &&
          identical(readBin(target, "raw", 100), as.raw(1:10)))
  unlink(dir, recursive = TRUE)

  cat(sprintf("\n%d failure%s\n", failures, if (failures == 1L) "" else "s"))
  if (failures) 1L else 0L
}

# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
# Run only when invoked as a script; `source()` loads the functions for use.
if (sys.nframe() == 0L) if (OPTS$mode == "self-test") {
  quit(status = self_test())
} else if (OPTS$mode == "calibrate") {
  run_calibration(OPTS$n, OPTS$cores, OPTS$bytes, OPTS$held_out)
} else if (OPTS$mode == "held-out-report") {
  existing <- if (file.exists(REPORT)) readLines(REPORT) else "# Symmetric-Cipher Randomness Report"
  section <- held_out_lines()
  write_atomic(REPORT, function(tmp)
    writeLines(splice_section(existing, "## Held-out calibration at the decision threshold", section), tmp))
  cat(sprintf("Held-out section written to %s\n", REPORT))
} else if (OPTS$mode == "calibration-report") {
  cal <- read_calibration(PG_BYTES)
  if (is.null(cal)) stop("no calibration data for battery ", BATTERY_VERSION,
                         " at ", PG_BYTES, " bytes in ", CAL_CSV)
  dir.create(PLOT_DIR, showWarnings = FALSE, recursive = TRUE)
  existing <- if (file.exists(REPORT)) readLines(REPORT) else "# Symmetric-Cipher Randomness Report"
  writeLines(splice_calibration(existing, calibration_lines(cal)), REPORT)
  cat(sprintf("Calibration section written to %s (%d streams)\n", REPORT, nrow(cal)))
} else {
  quit(status = run_battery())
}
