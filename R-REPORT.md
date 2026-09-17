# Symmetric-Cipher Randomness Report

Rendered 2026-09-17 07:09:43 PDT by `scripts/cipher_randomness.R` (battery version 4).
Toolchain: R version 4.2.0 (2022-04-22), base packages only.

**Plaintext.** Project Gutenberg #100 — *The Complete Works of William Shakespeare* (5,638,480 bytes; SHA-256 `3cf4b3d44ee14cff4e14e78e2ad3318eff76f3f7f2afc3cee6bb925879110a37`; byte-entropy 4.888696 bits/byte).

**Experiment identity.** Every ciphertext below was produced by the executable and plaintext named here and analysed by this script; the Ciphertexts section gives each one's digest and when it was encrypted and analysed.

| item | identity |
|------|----------|
| cryptography | commit `12506e375eaced530a366f4886a881df8de29baa`; uncommitted changes: none |
| rump | commit `ba318de957c8c7e3c0a098ea39fbc9ef07d6e3b6`; uncommitted changes: none |
| compiler | rustc 1.93.1 (01f6ddf75 2026-02-11); features: default |
| `cipher_encrypt` | SHA-256 `65be36f9f6c7f6b08efc97cb24a8bdb7f385fe26f8f1dd9b128c137e46113120` |
| script | SHA-256 `b8bcc491c7d398cc41a9434a0570f5b5bdfa1ca94ebb9d691aa8eb164b11d797` |

**Caveat.** Passing this battery is **necessary** for a usable symmetric primitive but is **not sufficient** for cryptographic security; the battery rules out gross statistical defects in the keystream, not key-recovery, distinguishing-attack, or related-key resistance.

**Method.** Each cipher encrypts the full plaintext under a fresh OS-random key.
Block ciphers run in CTR mode with a random IV; stream ciphers run in their native keystream mode.
The ciphertext is read three ways: as $L$ bytes, as $8L$ bits, and as $k = \lfloor L / 8 \rfloor$ = 704,810 values $u_j \in [0, 1)$, one per 8-byte chunk taken as a big-endian fraction (a double keeps the top 53 bits).

**Battery.** $m = 7$ tests, each with a parameter-free null distribution:

1. Byte-frequency $\chi^2$ over the 256 byte values of all $L$ bytes (Knuth, *TAOCP* Vol. 2, §3.3.2 A).
2. Kolmogorov-Smirnov test of $u$ against Uniform(0,1).
3. Serial test on disjoint pairs $(u_{2j}, u_{2j+1})$ in $16 \times 16$ cells (Knuth §3.3.2 B).
4. Gap test on $[0, 1/2)$ with the tail pooled so every expected count is at least 50 (Knuth §3.3.2 D).
5. Permutation test on disjoint 4-tuples, 24 orderings (Knuth §3.3.2 F).
6. Bartlett's cumulative periodogram test for a flat spectrum, on the leading 703,125 values of $u$ (the largest 5-smooth length, so the FFT is $O(n \log n)$).
7. Wald-Wolfowitz runs test on the full bit stream.

**Decision rule.** A cipher fails when any of its $m = 7$ p-values falls below $\alpha / m = 1.43 \times 10^{-4}$ (Bonferroni).  That bounds the probability that a good cipher fails by $\alpha = 0.001$ under any dependence among the tests only if every p-value is valid under the null, $\Pr(p \le t) \le t$; several tests take their p-values from asymptotic laws, so $\alpha$ is a nominal rate, and the calibration section reports the rates the battery attains on streams that are random by construction.  The `p < α` column counts the p-values below $\alpha$, which a good cipher shows at a rate of about $m \alpha = 0.007$ per battery.  A pass means only that these statistics did not detect a departure from independent uniform bytes; it is not evidence of key secrecy, authentication security or unpredictability.

**Entropy.** The plug-in byte entropy $H$ never exceeds $8$ bits; to second order $8 - H = \chi^2 / (2 L \ln 2)$ with $\chi^2$ the byte-frequency statistic, so under a uniform source $8 - H$ has mean $(K - 1) / (2 L \ln 2) = 3.26 \times 10^{-5}$ bits and standard deviation $\sqrt{2 (K - 1)} / (2 L \ln 2) = 2.89 \times 10^{-6}$ bits ($K = 256$, $L =$ 5,638,480).  Test 1 is therefore the calibrated form of the entropy check; $H$ is printed to six decimals as a description.

## Definitions

Let $b_0, b_1, \ldots, b_{L-1}$ be the ciphertext bytes and
$u_j = \sum_{i=0}^{7} b_{8j+i} \, 256^{-(i+1)}$ the chunk values; under $H_0$ the $u_j$ are independent Uniform(0,1).

| Symbol | Definition |
|--------|------------|
| $L$ | ciphertext length in bytes (equal to the plaintext length; CTR and keystream modes preserve length). |
| $k$ | number of chunk values, $\lfloor L / 8 \rfloor$. |
| $\alpha = 0.001$ | nominal family-wise error rate per cipher; each test rejects at $\alpha / m = 1.43 \times 10^{-4}$. |
| $p$ | classical p-value $\Pr(T \ge T_\mathrm{obs} \mid H_0)$; small $p$ rejects $H_0$. |
| $H$ | plug-in Shannon entropy of the byte distribution, in bits. |
| $m_k$ | the $k$-th raw sample moment of $u$; ideal $E[U^k] = 1/(k+1)$. |
| Fisher's $g$ | peak over mean of the periodogram at the non-zero Fourier frequencies. |
| `byte χ²` | byte frequency $\chi^2$ (256 cells): $\sum_v (c_v - L/256)^2 / (L/256)$ on the byte counts $c_v$, 255 degrees of freedom. |
| `KS` | Kolmogorov-Smirnov distance between the empirical distribution of $u$ and Uniform(0,1). |
| `serial` | $\chi^2$ with 255 degrees of freedom on the $16 \times 16$ cell counts of the pairs $(\lfloor 16 u_{2j} \rfloor, \lfloor 16 u_{2j+1} \rfloor)$. |
| `gap` | gap lengths for $u \in [0, 1/2)$, lengths $0, \ldots, t-1$ separate and $\ge t$ pooled with every expected count at least 50, $\chi^2$ with $t$ degrees of freedom. |
| `permutation` | $\chi^2$ with 23 degrees of freedom on the 24 orderings of the disjoint 4-tuples of $u$. |
| `Bartlett` | with $I_j$ the periodogram at Fourier frequency $j$ and $q = \lfloor (n-1)/2 \rfloor$, the KS distance of $C_i = \sum_{j \le i} I_j / \sum_{j \le q} I_j$, $i < q$, from Uniform(0,1). |
| `runs` | number of runs in the $8L$-bit stream against its Wald-Wolfowitz mean and variance, two-sided normal. |
| `p < α` | number of the $m$ p-values below $\alpha$. |
| `min p` | smallest of the $m$ p-values. |

## Summary

| cipher | token | $H$ (bits) | $8 - H$ (bits) | Fisher's $g$ | `p < α` | min p | verdict |
|--------|-------|------------|----------------|--------------|---------|-------|---------|
| AES-128 | `aes128` | 7.999968 | $3.22 \times 10^{-5}$ | 12.7 | 0 | 0.050 | PASS |
| AES-192 | `aes192` | 7.999965 | $3.50 \times 10^{-5}$ | 11.1 | 0 | 0.103 | PASS |
| AES-256 | `aes256` | 7.999969 | $3.11 \times 10^{-5}$ | 13.8 | 0 | 0.552 | PASS |
| Camellia-128 | `camellia128` | 7.999967 | $3.34 \times 10^{-5}$ | 14.6 | 0 | 0.013 | PASS |
| Camellia-192 | `camellia192` | 7.999963 | $3.67 \times 10^{-5}$ | 12.3 | 0 | 0.084 | PASS |
| Camellia-256 | `camellia256` | 7.999962 | $3.78 \times 10^{-5}$ | 13.8 | 0 | 0.019 | PASS |
| CAST-128 | `cast128` | 7.999967 | $3.33 \times 10^{-5}$ | 12.0 | 0 | 0.144 | PASS |
| DES | `des` | 7.999966 | $3.43 \times 10^{-5}$ | 13.7 | 0 | 0.041 | PASS |
| 3DES | `3des` | 7.999965 | $3.50 \times 10^{-5}$ | 13.1 | 0 | 0.058 | PASS |
| Kuznyechik | `grasshopper` | 7.999966 | $3.41 \times 10^{-5}$ | 13.5 | 0 | 0.066 | PASS |
| Magma | `magma` | 7.999969 | $3.14 \times 10^{-5}$ | 12.8 | 0 | 0.018 | PASS |
| PRESENT-80 | `present80` | 7.999970 | $3.03 \times 10^{-5}$ | 15.0 | 0 | 0.461 | PASS |
| PRESENT-128 | `present128` | 7.999968 | $3.21 \times 10^{-5}$ | 13.8 | 0 | 0.063 | PASS |
| SEED | `seed` | 7.999969 | $3.09 \times 10^{-5}$ | 12.4 | 0 | 0.123 | PASS |
| Serpent-128 | `serpent128` | 7.999966 | $3.38 \times 10^{-5}$ | 11.7 | 0 | 0.163 | PASS |
| Serpent-192 | `serpent192` | 7.999964 | $3.61 \times 10^{-5}$ | 12.4 | 0 | 0.118 | PASS |
| Serpent-256 | `serpent256` | 7.999971 | $2.86 \times 10^{-5}$ | 13.6 | 0 | 0.021 | PASS |
| SM4 | `sm4` | 7.999971 | $2.94 \times 10^{-5}$ | 12.4 | 0 | 0.014 | PASS |
| Twofish-128 | `twofish128` | 7.999967 | $3.30 \times 10^{-5}$ | 12.8 | 0 | 0.183 | PASS |
| Twofish-256 | `twofish256` | 7.999967 | $3.26 \times 10^{-5}$ | 12.4 | 0 | 0.215 | PASS |
| Simon32/64 | `simon32_64` | 7.999964 | $3.61 \times 10^{-5}$ | 12.8 | 0 | 0.119 | PASS |
| Simon64/128 | `simon64_128` | 7.999966 | $3.43 \times 10^{-5}$ | 12.2 | 0 | 0.095 | PASS |
| Simon128/128 | `simon128_128` | 7.999968 | $3.17 \times 10^{-5}$ | 12.5 | 0 | 0.062 | PASS |
| Simon128/256 | `simon128_256` | 7.999963 | $3.66 \times 10^{-5}$ | 12.1 | 0 | 0.087 | PASS |
| Speck32/64 | `speck32_64` | 7.999968 | $3.20 \times 10^{-5}$ | 14.6 | 0 | 0.195 | PASS |
| Speck64/128 | `speck64_128` | 7.999965 | $3.52 \times 10^{-5}$ | 17.7 | 0 | 0.119 | PASS |
| Speck128/128 | `speck128_128` | 7.999968 | $3.24 \times 10^{-5}$ | 13.6 | 0 | 0.023 | PASS |
| Speck128/256 | `speck128_256` | 7.999968 | $3.15 \times 10^{-5}$ | 11.7 | 0 | 0.639 | PASS |
| ChaCha20 | `chacha20` | 7.999968 | $3.21 \times 10^{-5}$ | 12.2 | 0 | 0.073 | PASS |
| XChaCha20 | `xchacha20` | 7.999968 | $3.20 \times 10^{-5}$ | 13.9 | 0 | 0.001 | PASS |
| Salsa20 | `salsa20` | 7.999965 | $3.52 \times 10^{-5}$ | 14.6 | 0 | 0.181 | PASS |
| Rabbit | `rabbit` | 7.999971 | $2.87 \times 10^{-5}$ | 12.4 | 0 | 0.206 | PASS |
| ZUC-128 | `zuc128` | 7.999964 | $3.61 \times 10^{-5}$ | 13.5 | 0 | 0.114 | PASS |
| SNOW 3G | `snow3g` | 7.999966 | $3.41 \times 10^{-5}$ | 12.7 | 0 | 0.137 | PASS |

**All 34 ciphers pass the battery.**

## Ciphertexts

| cipher | ciphertext SHA-256 | bytes | encrypted | analysed |
|--------|--------------------|-------|-----------|----------|
| AES-128 | `bd046ebfb3b154b7b78ec41d7e4a2b18dbb74553618cdcea035b0a1162730f07` | 5,638,480 | 2026-09-16 23:51:34 PDT | 2026-09-17 07:08:52 PDT |
| AES-192 | `80cea69667d4c01d98221d359ce9dd28d07aaec7c46b0f3d75789f430737b81e` | 5,638,480 | 2026-09-16 23:48:52 PDT | 2026-09-17 07:08:53 PDT |
| AES-256 | `9b5808189078ab941a36094951883774a8fb41a496f07796b9a9ff3265c22bdd` | 5,638,480 | 2026-09-16 23:48:52 PDT | 2026-09-17 07:08:54 PDT |
| Camellia-128 | `921ae37f9e0fb2f2f775c39217e0f91014b46672a5e32d6eda5177d2209ca44b` | 5,638,480 | 2026-09-16 23:48:53 PDT | 2026-09-17 07:08:55 PDT |
| Camellia-192 | `fd1c4081a00c78bb2db9230063d91a97eecb3b8f19350afd5f41e22faf0c713e` | 5,638,480 | 2026-09-16 23:48:54 PDT | 2026-09-17 07:08:56 PDT |
| Camellia-256 | `4173ec8733eeb30901904681f375cf80b1788cd993ca072acb1f08b326368772` | 5,638,480 | 2026-09-16 23:48:54 PDT | 2026-09-17 07:08:57 PDT |
| CAST-128 | `a9d0ddd6e06bb6ee977219706e13b9b53baebc788a2420f77a5891b5a10603da` | 5,638,480 | 2026-09-16 23:48:56 PDT | 2026-09-17 07:08:59 PDT |
| DES | `d7ef01b3086d008f76323fd212ed49e3cacf8f46f4e9ea8bfd74dbff62a9bd59` | 5,638,480 | 2026-09-16 23:48:57 PDT | 2026-09-17 07:09:00 PDT |
| 3DES | `2cba7b1789089a765dcc2d9c1979c2b865ac986e1dc14d2463cc1a8be9f8c17a` | 5,638,480 | 2026-09-16 23:48:58 PDT | 2026-09-17 07:09:01 PDT |
| Kuznyechik | `31fb6a83964e15e8c575440d5f7df1605c71329cb3eedebfeb16b98511a64660` | 5,638,480 | 2026-09-16 23:48:58 PDT | 2026-09-17 07:09:02 PDT |
| Magma | `15d95d271dac78319bcb2633ee26fa21a4cd2497761bd780d5bb0d137fbfe0bb` | 5,638,480 | 2026-09-16 23:48:59 PDT | 2026-09-17 07:09:03 PDT |
| PRESENT-80 | `f966232f4f174270c0043e6b719a1ad74b88cda7883093dee29faf2dccaadc0b` | 5,638,480 | 2026-09-16 23:49:01 PDT | 2026-09-17 07:09:04 PDT |
| PRESENT-128 | `5f097f3a01c1082ad646fd3fe19fabebc1e286e471f07f1f0bbe637ede4f58af` | 5,638,480 | 2026-09-16 23:49:03 PDT | 2026-09-17 07:09:05 PDT |
| SEED | `4ae7920aa61552c016d3f8eb7ada229f7598a51ca86ca04fcf64b9a47973d6ef` | 5,638,480 | 2026-09-16 23:49:04 PDT | 2026-09-17 07:09:07 PDT |
| Serpent-128 | `209cb842e81fa1e18ec584c597a5590887444c6220988e97b0ba07f162e49f34` | 5,638,480 | 2026-09-16 23:49:05 PDT | 2026-09-17 07:09:09 PDT |
| Serpent-192 | `6cec841aaa96b7b2e0d895966bab1c7822f0adb3ced915c9f31611ee4ca4acb7` | 5,638,480 | 2026-09-16 23:49:06 PDT | 2026-09-17 07:09:10 PDT |
| Serpent-256 | `f1ec46d094397032a83b165e144974bbdac5cdbce2711ee58750cbe7a4634ee4` | 5,638,480 | 2026-09-16 23:49:07 PDT | 2026-09-17 07:09:12 PDT |
| SM4 | `6f64ca3a60c828285150acf40b2804f4e64414c58429ae3244faa6f64870597e` | 5,638,480 | 2026-09-16 23:49:08 PDT | 2026-09-17 07:09:14 PDT |
| Twofish-128 | `596750289de3e08a7280c6c52704fef09efead1736aaaa31873e4adb1955ec31` | 5,638,480 | 2026-09-16 23:49:10 PDT | 2026-09-17 07:09:16 PDT |
| Twofish-256 | `29b1443635f48eb08cfa7af09b8896cb075c810e5a0335bb8a8551efa746df5a` | 5,638,480 | 2026-09-16 23:49:11 PDT | 2026-09-17 07:09:17 PDT |
| Simon32/64 | `816f7d55ee2fd2facf83c9144f9a5f3a4075799e7768379767150ca2683755d7` | 5,638,480 | 2026-09-16 23:49:12 PDT | 2026-09-17 07:09:19 PDT |
| Simon64/128 | `bbb8b7aa216a8f847dd9d0cef5670b0c7e90cc594107959c5534487cb4cac281` | 5,638,480 | 2026-09-16 23:49:13 PDT | 2026-09-17 07:09:21 PDT |
| Simon128/128 | `d1884ff82a2c102378e3fd093f489ae3ab20681bfe0fc51e2b8424a77d6ceed9` | 5,638,480 | 2026-09-16 23:49:14 PDT | 2026-09-17 07:09:22 PDT |
| Simon128/256 | `d506fca142b62cea6071a196337b5d1ca44e3f31e1e51158e50f6e1947d9a881` | 5,638,480 | 2026-09-16 23:49:14 PDT | 2026-09-17 07:09:23 PDT |
| Speck32/64 | `34baf44f75e05f5938b2fc92038f43ca881fd7b96ee94259049dff763e09e2d4` | 5,638,480 | 2026-09-16 23:49:15 PDT | 2026-09-17 07:09:25 PDT |
| Speck64/128 | `1f5beb654dc3459a51987cfb7178f7792c68ffcefcf96b99328f803d26372ac9` | 5,638,480 | 2026-09-16 23:49:16 PDT | 2026-09-17 07:09:26 PDT |
| Speck128/128 | `77e665b75cac90e362c3305efbf189b7a35763eb9a818af2e4dbed14279c1dbb` | 5,638,480 | 2026-09-16 23:49:17 PDT | 2026-09-17 07:09:28 PDT |
| Speck128/256 | `15c1ce8dc43e1b8fa12ac21621cb08131f63e815565bba3585a6d22592c7fb5e` | 5,638,480 | 2026-09-16 23:49:18 PDT | 2026-09-17 07:09:29 PDT |
| ChaCha20 | `3e69382d947854b633cb35c25b108a77c1870eada3767817f7c4b016142d1d74` | 5,638,480 | 2026-09-16 23:49:19 PDT | 2026-09-17 07:09:30 PDT |
| XChaCha20 | `bc0248a947ce9dcf13cf43ce82da2cf41d84a5b7507154d51130d1f504069bc7` | 5,638,480 | 2026-09-16 23:49:20 PDT | 2026-09-17 07:09:32 PDT |
| Salsa20 | `93fe45a86b990dc87d78954e80c1cc22939945bae058a678fd72d6966c0cfc24` | 5,638,480 | 2026-09-16 23:49:22 PDT | 2026-09-17 07:09:33 PDT |
| Rabbit | `9c9ce2cd792fcee008c25dfcdf54741fe8612b3100d6ca31f529f7263c7ae36e` | 5,638,480 | 2026-09-16 23:49:24 PDT | 2026-09-17 07:09:34 PDT |
| ZUC-128 | `4d5ddabf60d11066b4be95e8ef597560a3a8bfe97633220d4aaff74792a5e880` | 5,638,480 | 2026-09-16 23:49:25 PDT | 2026-09-17 07:09:35 PDT |
| SNOW 3G | `a251a3118863856cd2e94509a62248fb949c74c5c6aa3e3be0e7d4e557bf5724` | 5,638,480 | 2026-09-16 23:49:26 PDT | 2026-09-17 07:09:37 PDT |

## Per-cipher detail

### AES-128 (`aes128`)

Verdict: PASS &mdash; min p = 0.050 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.22 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.71$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.543 |
| KS vs Uniform(0,1) | 0.853 |
| serial test (pairs, $16 \times 16$ cells) | 0.794 |
| gap test (Knuth, $[0, 1/2)$) | 0.050 |
| permutation test ($d = 4$) | 0.080 |
| cumulative periodogram (Bartlett) | 0.594 |
| runs test (bit stream) | 0.952 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500005 | 0.500000 | 4.67e-06 |
| 2 | 0.333260 | 0.333333 | 7.31e-05 |
| 3 | 0.249910 | 0.250000 | 8.98e-05 |
| 4 | 0.199920 | 0.200000 | 7.98e-05 |
| 5 | 0.166606 | 0.166667 | 6.06e-05 |
| 6 | 0.142818 | 0.142857 | 3.87e-05 |
| 7 | 0.124983 | 0.125000 | 1.68e-05 |
| 8 | 0.111115 | 0.111111 | 4.34e-06 |
| 9 | 0.100024 | 0.100000 | 2.41e-05 |
| 10 | 0.090951 | 0.090909 | 4.23e-05 |

![spectrum](scripts/cipher_plots/aes128.png)

### AES-192 (`aes192`)

Verdict: PASS &mdash; min p = 0.103 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999965$ bits ($8 - H = 3.50 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 11.13$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.204 |
| KS vs Uniform(0,1) | 0.103 |
| serial test (pairs, $16 \times 16$ cells) | 0.907 |
| gap test (Knuth, $[0, 1/2)$) | 0.413 |
| permutation test ($d = 4$) | 0.288 |
| cumulative periodogram (Bartlett) | 0.199 |
| runs test (bit stream) | 0.223 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500543 | 0.500000 | 5.43e-04 |
| 2 | 0.333943 | 0.333333 | 6.09e-04 |
| 3 | 0.250569 | 0.250000 | 5.69e-04 |
| 4 | 0.200512 | 0.200000 | 5.12e-04 |
| 5 | 0.167126 | 0.166667 | 4.59e-04 |
| 6 | 0.143272 | 0.142857 | 4.15e-04 |
| 7 | 0.125378 | 0.125000 | 3.78e-04 |
| 8 | 0.111458 | 0.111111 | 3.47e-04 |
| 9 | 0.100321 | 0.100000 | 3.21e-04 |
| 10 | 0.091209 | 0.090909 | 3.00e-04 |

![spectrum](scripts/cipher_plots/aes192.png)

### AES-256 (`aes256`)

Verdict: PASS &mdash; min p = 0.552 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999969$ bits ($8 - H = 3.11 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.78$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.697 |
| KS vs Uniform(0,1) | 0.644 |
| serial test (pairs, $16 \times 16$ cells) | 0.552 |
| gap test (Knuth, $[0, 1/2)$) | 0.821 |
| permutation test ($d = 4$) | 0.986 |
| cumulative periodogram (Bartlett) | 0.663 |
| runs test (bit stream) | 0.984 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500256 | 0.500000 | 2.56e-04 |
| 2 | 0.333460 | 0.333333 | 1.26e-04 |
| 3 | 0.250031 | 0.250000 | 3.12e-05 |
| 4 | 0.199971 | 0.200000 | 2.93e-05 |
| 5 | 0.166599 | 0.166667 | 6.73e-05 |
| 6 | 0.142766 | 0.142857 | 9.10e-05 |
| 7 | 0.124895 | 0.125000 | 1.05e-04 |
| 8 | 0.110997 | 0.111111 | 1.14e-04 |
| 9 | 0.099881 | 0.100000 | 1.19e-04 |
| 10 | 0.090788 | 0.090909 | 1.21e-04 |

![spectrum](scripts/cipher_plots/aes256.png)

### Camellia-128 (`camellia128`)

Verdict: PASS &mdash; min p = 0.013 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999967$ bits ($8 - H = 3.34 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 14.64$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.386 |
| KS vs Uniform(0,1) | 0.013 |
| serial test (pairs, $16 \times 16$ cells) | 0.116 |
| gap test (Knuth, $[0, 1/2)$) | 0.065 |
| permutation test ($d = 4$) | 0.264 |
| cumulative periodogram (Bartlett) | 0.741 |
| runs test (bit stream) | 0.569 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499174 | 0.500000 | 8.26e-04 |
| 2 | 0.332508 | 0.333333 | 8.25e-04 |
| 3 | 0.249273 | 0.250000 | 7.27e-04 |
| 4 | 0.199370 | 0.200000 | 6.30e-04 |
| 5 | 0.166118 | 0.166667 | 5.49e-04 |
| 6 | 0.142375 | 0.142857 | 4.83e-04 |
| 7 | 0.124572 | 0.125000 | 4.28e-04 |
| 8 | 0.110728 | 0.111111 | 3.83e-04 |
| 9 | 0.099655 | 0.100000 | 3.45e-04 |
| 10 | 0.090598 | 0.090909 | 3.11e-04 |

![spectrum](scripts/cipher_plots/camellia128.png)

### Camellia-192 (`camellia192`)

Verdict: PASS &mdash; min p = 0.084 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999963$ bits ($8 - H = 3.67 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.27$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.084 |
| KS vs Uniform(0,1) | 0.412 |
| serial test (pairs, $16 \times 16$ cells) | 0.703 |
| gap test (Knuth, $[0, 1/2)$) | 0.728 |
| permutation test ($d = 4$) | 0.933 |
| cumulative periodogram (Bartlett) | 0.614 |
| runs test (bit stream) | 0.184 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500256 | 0.500000 | 2.56e-04 |
| 2 | 0.333600 | 0.333333 | 2.67e-04 |
| 3 | 0.250232 | 0.250000 | 2.32e-04 |
| 4 | 0.200204 | 0.200000 | 2.04e-04 |
| 5 | 0.166853 | 0.166667 | 1.87e-04 |
| 6 | 0.143034 | 0.142857 | 1.77e-04 |
| 7 | 0.125171 | 0.125000 | 1.71e-04 |
| 8 | 0.111279 | 0.111111 | 1.67e-04 |
| 9 | 0.100164 | 0.100000 | 1.64e-04 |
| 10 | 0.091070 | 0.090909 | 1.61e-04 |

![spectrum](scripts/cipher_plots/camellia192.png)

### Camellia-256 (`camellia256`)

Verdict: PASS &mdash; min p = 0.019 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999962$ bits ($8 - H = 3.78 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.77$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.042 |
| KS vs Uniform(0,1) | 0.541 |
| serial test (pairs, $16 \times 16$ cells) | 0.860 |
| gap test (Knuth, $[0, 1/2)$) | 0.583 |
| permutation test ($d = 4$) | 0.311 |
| cumulative periodogram (Bartlett) | 0.622 |
| runs test (bit stream) | 0.019 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500205 | 0.500000 | 2.05e-04 |
| 2 | 0.333605 | 0.333333 | 2.71e-04 |
| 3 | 0.250315 | 0.250000 | 3.15e-04 |
| 4 | 0.200346 | 0.200000 | 3.46e-04 |
| 5 | 0.167032 | 0.166667 | 3.66e-04 |
| 6 | 0.143235 | 0.142857 | 3.78e-04 |
| 7 | 0.125385 | 0.125000 | 3.85e-04 |
| 8 | 0.111500 | 0.111111 | 3.89e-04 |
| 9 | 0.100391 | 0.100000 | 3.91e-04 |
| 10 | 0.091300 | 0.090909 | 3.91e-04 |

![spectrum](scripts/cipher_plots/camellia256.png)

### CAST-128 (`cast128`)

Verdict: PASS &mdash; min p = 0.144 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999967$ bits ($8 - H = 3.33 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.02$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.399 |
| KS vs Uniform(0,1) | 0.144 |
| serial test (pairs, $16 \times 16$ cells) | 0.302 |
| gap test (Knuth, $[0, 1/2)$) | 0.607 |
| permutation test ($d = 4$) | 0.373 |
| cumulative periodogram (Bartlett) | 0.382 |
| runs test (bit stream) | 0.531 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499797 | 0.500000 | 2.03e-04 |
| 2 | 0.333229 | 0.333333 | 1.04e-04 |
| 3 | 0.250025 | 0.250000 | 2.48e-05 |
| 4 | 0.200122 | 0.200000 | 1.22e-04 |
| 5 | 0.166852 | 0.166667 | 1.86e-04 |
| 6 | 0.143083 | 0.142857 | 2.26e-04 |
| 7 | 0.125250 | 0.125000 | 2.50e-04 |
| 8 | 0.111374 | 0.111111 | 2.63e-04 |
| 9 | 0.100270 | 0.100000 | 2.70e-04 |
| 10 | 0.091182 | 0.090909 | 2.73e-04 |

![spectrum](scripts/cipher_plots/cast128.png)

### DES (`des`)

Verdict: PASS &mdash; min p = 0.041 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999966$ bits ($8 - H = 3.43 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.72$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.270 |
| KS vs Uniform(0,1) | 0.913 |
| serial test (pairs, $16 \times 16$ cells) | 0.398 |
| gap test (Knuth, $[0, 1/2)$) | 0.628 |
| permutation test ($d = 4$) | 0.041 |
| cumulative periodogram (Bartlett) | 0.365 |
| runs test (bit stream) | 0.613 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500040 | 0.500000 | 4.02e-05 |
| 2 | 0.333320 | 0.333333 | 1.32e-05 |
| 3 | 0.249931 | 0.250000 | 6.92e-05 |
| 4 | 0.199895 | 0.200000 | 1.05e-04 |
| 5 | 0.166541 | 0.166667 | 1.25e-04 |
| 6 | 0.142722 | 0.142857 | 1.35e-04 |
| 7 | 0.124861 | 0.125000 | 1.39e-04 |
| 8 | 0.110973 | 0.111111 | 1.39e-04 |
| 9 | 0.099864 | 0.100000 | 1.36e-04 |
| 10 | 0.090777 | 0.090909 | 1.32e-04 |

![spectrum](scripts/cipher_plots/des.png)

### 3DES (`3des`)

Verdict: PASS &mdash; min p = 0.058 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999965$ bits ($8 - H = 3.50 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.06$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.203 |
| KS vs Uniform(0,1) | 0.058 |
| serial test (pairs, $16 \times 16$ cells) | 0.146 |
| gap test (Knuth, $[0, 1/2)$) | 0.128 |
| permutation test ($d = 4$) | 0.402 |
| cumulative periodogram (Bartlett) | 0.212 |
| runs test (bit stream) | 0.504 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499318 | 0.500000 | 6.82e-04 |
| 2 | 0.332549 | 0.333333 | 7.84e-04 |
| 3 | 0.249280 | 0.250000 | 7.20e-04 |
| 4 | 0.199369 | 0.200000 | 6.31e-04 |
| 5 | 0.166119 | 0.166667 | 5.48e-04 |
| 6 | 0.142381 | 0.142857 | 4.76e-04 |
| 7 | 0.124584 | 0.125000 | 4.16e-04 |
| 8 | 0.110746 | 0.111111 | 3.65e-04 |
| 9 | 0.099678 | 0.100000 | 3.22e-04 |
| 10 | 0.090623 | 0.090909 | 2.86e-04 |

![spectrum](scripts/cipher_plots/3des.png)

### Kuznyechik (`grasshopper`)

Verdict: PASS &mdash; min p = 0.066 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999966$ bits ($8 - H = 3.41 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.45$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.295 |
| KS vs Uniform(0,1) | 0.536 |
| serial test (pairs, $16 \times 16$ cells) | 0.896 |
| gap test (Knuth, $[0, 1/2)$) | 0.222 |
| permutation test ($d = 4$) | 0.530 |
| cumulative periodogram (Bartlett) | 0.804 |
| runs test (bit stream) | 0.066 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500308 | 0.500000 | 3.08e-04 |
| 2 | 0.333573 | 0.333333 | 2.40e-04 |
| 3 | 0.250194 | 0.250000 | 1.94e-04 |
| 4 | 0.200168 | 0.200000 | 1.68e-04 |
| 5 | 0.166821 | 0.166667 | 1.54e-04 |
| 6 | 0.143004 | 0.142857 | 1.47e-04 |
| 7 | 0.125143 | 0.125000 | 1.43e-04 |
| 8 | 0.111251 | 0.111111 | 1.40e-04 |
| 9 | 0.100138 | 0.100000 | 1.38e-04 |
| 10 | 0.091045 | 0.090909 | 1.36e-04 |

![spectrum](scripts/cipher_plots/grasshopper.png)

### Magma (`magma`)

Verdict: PASS &mdash; min p = 0.018 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999969$ bits ($8 - H = 3.14 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.76$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.660 |
| KS vs Uniform(0,1) | 0.162 |
| serial test (pairs, $16 \times 16$ cells) | 0.278 |
| gap test (Knuth, $[0, 1/2)$) | 0.133 |
| permutation test ($d = 4$) | 0.018 |
| cumulative periodogram (Bartlett) | 0.323 |
| runs test (bit stream) | 0.495 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500612 | 0.500000 | 6.12e-04 |
| 2 | 0.333934 | 0.333333 | 6.00e-04 |
| 3 | 0.250531 | 0.250000 | 5.31e-04 |
| 4 | 0.200464 | 0.200000 | 4.64e-04 |
| 5 | 0.167076 | 0.166667 | 4.09e-04 |
| 6 | 0.143221 | 0.142857 | 3.64e-04 |
| 7 | 0.125328 | 0.125000 | 3.28e-04 |
| 8 | 0.111410 | 0.111111 | 2.99e-04 |
| 9 | 0.100275 | 0.100000 | 2.75e-04 |
| 10 | 0.091163 | 0.090909 | 2.54e-04 |

![spectrum](scripts/cipher_plots/magma.png)

### PRESENT-80 (`present80`)

Verdict: PASS &mdash; min p = 0.461 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999970$ bits ($8 - H = 3.03 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 15.04$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.785 |
| KS vs Uniform(0,1) | 0.923 |
| serial test (pairs, $16 \times 16$ cells) | 0.475 |
| gap test (Knuth, $[0, 1/2)$) | 0.742 |
| permutation test ($d = 4$) | 0.577 |
| cumulative periodogram (Bartlett) | 0.909 |
| runs test (bit stream) | 0.461 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500107 | 0.500000 | 1.07e-04 |
| 2 | 0.333506 | 0.333333 | 1.73e-04 |
| 3 | 0.250191 | 0.250000 | 1.91e-04 |
| 4 | 0.200192 | 0.200000 | 1.92e-04 |
| 5 | 0.166852 | 0.166667 | 1.85e-04 |
| 6 | 0.143034 | 0.142857 | 1.77e-04 |
| 7 | 0.125168 | 0.125000 | 1.68e-04 |
| 8 | 0.111272 | 0.111111 | 1.60e-04 |
| 9 | 0.100154 | 0.100000 | 1.54e-04 |
| 10 | 0.091057 | 0.090909 | 1.48e-04 |

![spectrum](scripts/cipher_plots/present80.png)

### PRESENT-128 (`present128`)

Verdict: PASS &mdash; min p = 0.063 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.21 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.82$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.561 |
| KS vs Uniform(0,1) | 0.704 |
| serial test (pairs, $16 \times 16$ cells) | 0.063 |
| gap test (Knuth, $[0, 1/2)$) | 0.567 |
| permutation test ($d = 4$) | 0.904 |
| cumulative periodogram (Bartlett) | 0.605 |
| runs test (bit stream) | 0.958 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500083 | 0.500000 | 8.33e-05 |
| 2 | 0.333496 | 0.333333 | 1.63e-04 |
| 3 | 0.250187 | 0.250000 | 1.87e-04 |
| 4 | 0.200186 | 0.200000 | 1.86e-04 |
| 5 | 0.166843 | 0.166667 | 1.76e-04 |
| 6 | 0.143021 | 0.142857 | 1.64e-04 |
| 7 | 0.125152 | 0.125000 | 1.52e-04 |
| 8 | 0.111254 | 0.111111 | 1.43e-04 |
| 9 | 0.100135 | 0.100000 | 1.35e-04 |
| 10 | 0.091038 | 0.090909 | 1.29e-04 |

![spectrum](scripts/cipher_plots/present128.png)

### SEED (`seed`)

Verdict: PASS &mdash; min p = 0.123 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999969$ bits ($8 - H = 3.09 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.39$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.717 |
| KS vs Uniform(0,1) | 0.355 |
| serial test (pairs, $16 \times 16$ cells) | 0.833 |
| gap test (Knuth, $[0, 1/2)$) | 0.173 |
| permutation test ($d = 4$) | 0.176 |
| cumulative periodogram (Bartlett) | 0.123 |
| runs test (bit stream) | 0.780 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500264 | 0.500000 | 2.64e-04 |
| 2 | 0.333620 | 0.333333 | 2.87e-04 |
| 3 | 0.250249 | 0.250000 | 2.49e-04 |
| 4 | 0.200196 | 0.200000 | 1.96e-04 |
| 5 | 0.166811 | 0.166667 | 1.44e-04 |
| 6 | 0.142955 | 0.142857 | 9.82e-05 |
| 7 | 0.125059 | 0.125000 | 5.95e-05 |
| 8 | 0.111139 | 0.111111 | 2.74e-05 |
| 9 | 0.100001 | 0.100000 | 9.61e-07 |
| 10 | 0.090888 | 0.090909 | 2.08e-05 |

![spectrum](scripts/cipher_plots/seed.png)

### Serpent-128 (`serpent128`)

Verdict: PASS &mdash; min p = 0.163 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999966$ bits ($8 - H = 3.38 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 11.70$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.335 |
| KS vs Uniform(0,1) | 0.896 |
| serial test (pairs, $16 \times 16$ cells) | 0.320 |
| gap test (Knuth, $[0, 1/2)$) | 0.326 |
| permutation test ($d = 4$) | 0.163 |
| cumulative periodogram (Bartlett) | 0.944 |
| runs test (bit stream) | 0.691 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499805 | 0.500000 | 1.95e-04 |
| 2 | 0.333174 | 0.333333 | 1.60e-04 |
| 3 | 0.249865 | 0.250000 | 1.35e-04 |
| 4 | 0.199886 | 0.200000 | 1.14e-04 |
| 5 | 0.166573 | 0.166667 | 9.42e-05 |
| 6 | 0.142780 | 0.142857 | 7.73e-05 |
| 7 | 0.124936 | 0.125000 | 6.40e-05 |
| 8 | 0.111057 | 0.111111 | 5.40e-05 |
| 9 | 0.099953 | 0.100000 | 4.69e-05 |
| 10 | 0.090867 | 0.090909 | 4.24e-05 |

![spectrum](scripts/cipher_plots/serpent128.png)

### Serpent-192 (`serpent192`)

Verdict: PASS &mdash; min p = 0.118 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999964$ bits ($8 - H = 3.61 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.39$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.118 |
| KS vs Uniform(0,1) | 0.751 |
| serial test (pairs, $16 \times 16$ cells) | 0.968 |
| gap test (Knuth, $[0, 1/2)$) | 0.349 |
| permutation test ($d = 4$) | 0.223 |
| cumulative periodogram (Bartlett) | 0.462 |
| runs test (bit stream) | 0.203 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499773 | 0.500000 | 2.27e-04 |
| 2 | 0.333140 | 0.333333 | 1.93e-04 |
| 3 | 0.249865 | 0.250000 | 1.35e-04 |
| 4 | 0.199916 | 0.200000 | 8.38e-05 |
| 5 | 0.166626 | 0.166667 | 4.09e-05 |
| 6 | 0.142852 | 0.142857 | 5.56e-06 |
| 7 | 0.125023 | 0.125000 | 2.34e-05 |
| 8 | 0.111159 | 0.111111 | 4.74e-05 |
| 9 | 0.100067 | 0.100000 | 6.73e-05 |
| 10 | 0.090993 | 0.090909 | 8.39e-05 |

![spectrum](scripts/cipher_plots/serpent192.png)

### Serpent-256 (`serpent256`)

Verdict: PASS &mdash; min p = 0.021 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999971$ bits ($8 - H = 2.86 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.59$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.921 |
| KS vs Uniform(0,1) | 0.985 |
| serial test (pairs, $16 \times 16$ cells) | 0.463 |
| gap test (Knuth, $[0, 1/2)$) | 0.431 |
| permutation test ($d = 4$) | 0.716 |
| cumulative periodogram (Bartlett) | 0.021 |
| runs test (bit stream) | 0.221 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499805 | 0.500000 | 1.95e-04 |
| 2 | 0.333156 | 0.333333 | 1.77e-04 |
| 3 | 0.249835 | 0.250000 | 1.65e-04 |
| 4 | 0.199849 | 0.200000 | 1.51e-04 |
| 5 | 0.166530 | 0.166667 | 1.37e-04 |
| 6 | 0.142734 | 0.142857 | 1.23e-04 |
| 7 | 0.124889 | 0.125000 | 1.11e-04 |
| 8 | 0.111011 | 0.111111 | 9.99e-05 |
| 9 | 0.099910 | 0.100000 | 8.99e-05 |
| 10 | 0.090828 | 0.090909 | 8.10e-05 |

![spectrum](scripts/cipher_plots/serpent256.png)

### SM4 (`sm4`)

Verdict: PASS &mdash; min p = 0.014 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999971$ bits ($8 - H = 2.94 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.38$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.867 |
| KS vs Uniform(0,1) | 0.014 |
| serial test (pairs, $16 \times 16$ cells) | 0.213 |
| gap test (Knuth, $[0, 1/2)$) | 0.207 |
| permutation test ($d = 4$) | 0.134 |
| cumulative periodogram (Bartlett) | 0.701 |
| runs test (bit stream) | 0.389 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499274 | 0.500000 | 7.26e-04 |
| 2 | 0.332607 | 0.333333 | 7.27e-04 |
| 3 | 0.249353 | 0.250000 | 6.47e-04 |
| 4 | 0.199442 | 0.200000 | 5.58e-04 |
| 5 | 0.166189 | 0.166667 | 4.78e-04 |
| 6 | 0.142446 | 0.142857 | 4.11e-04 |
| 7 | 0.124643 | 0.125000 | 3.57e-04 |
| 8 | 0.110797 | 0.111111 | 3.14e-04 |
| 9 | 0.099719 | 0.100000 | 2.81e-04 |
| 10 | 0.090655 | 0.090909 | 2.54e-04 |

![spectrum](scripts/cipher_plots/sm4.png)

### Twofish-128 (`twofish128`)

Verdict: PASS &mdash; min p = 0.183 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999967$ bits ($8 - H = 3.30 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.78$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.433 |
| KS vs Uniform(0,1) | 0.536 |
| serial test (pairs, $16 \times 16$ cells) | 0.518 |
| gap test (Knuth, $[0, 1/2)$) | 0.183 |
| permutation test ($d = 4$) | 0.521 |
| cumulative periodogram (Bartlett) | 0.887 |
| runs test (bit stream) | 0.456 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500194 | 0.500000 | 1.94e-04 |
| 2 | 0.333536 | 0.333333 | 2.03e-04 |
| 3 | 0.250203 | 0.250000 | 2.03e-04 |
| 4 | 0.200190 | 0.200000 | 1.90e-04 |
| 5 | 0.166838 | 0.166667 | 1.71e-04 |
| 6 | 0.143009 | 0.142857 | 1.52e-04 |
| 7 | 0.125134 | 0.125000 | 1.34e-04 |
| 8 | 0.111230 | 0.111111 | 1.19e-04 |
| 9 | 0.100106 | 0.100000 | 1.06e-04 |
| 10 | 0.091005 | 0.090909 | 9.63e-05 |

![spectrum](scripts/cipher_plots/twofish128.png)

### Twofish-256 (`twofish256`)

Verdict: PASS &mdash; min p = 0.215 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999967$ bits ($8 - H = 3.26 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.42$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.492 |
| KS vs Uniform(0,1) | 0.477 |
| serial test (pairs, $16 \times 16$ cells) | 0.324 |
| gap test (Knuth, $[0, 1/2)$) | 0.527 |
| permutation test ($d = 4$) | 0.451 |
| cumulative periodogram (Bartlett) | 0.934 |
| runs test (bit stream) | 0.215 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499881 | 0.500000 | 1.19e-04 |
| 2 | 0.333409 | 0.333333 | 7.60e-05 |
| 3 | 0.250214 | 0.250000 | 2.14e-04 |
| 4 | 0.200293 | 0.200000 | 2.93e-04 |
| 5 | 0.167003 | 0.166667 | 3.36e-04 |
| 6 | 0.143213 | 0.142857 | 3.56e-04 |
| 7 | 0.125363 | 0.125000 | 3.63e-04 |
| 8 | 0.111473 | 0.111111 | 3.62e-04 |
| 9 | 0.100356 | 0.100000 | 3.56e-04 |
| 10 | 0.091256 | 0.090909 | 3.47e-04 |

![spectrum](scripts/cipher_plots/twofish256.png)

### Simon32/64 (`simon32_64`)

Verdict: PASS &mdash; min p = 0.119 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999964$ bits ($8 - H = 3.61 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.82$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.119 |
| KS vs Uniform(0,1) | 0.290 |
| serial test (pairs, $16 \times 16$ cells) | 0.650 |
| gap test (Knuth, $[0, 1/2)$) | 0.808 |
| permutation test ($d = 4$) | 0.646 |
| cumulative periodogram (Bartlett) | 0.851 |
| runs test (bit stream) | 0.636 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500066 | 0.500000 | 6.63e-05 |
| 2 | 0.333433 | 0.333333 | 9.96e-05 |
| 3 | 0.250088 | 0.250000 | 8.76e-05 |
| 4 | 0.200052 | 0.200000 | 5.19e-05 |
| 5 | 0.166673 | 0.166667 | 6.60e-06 |
| 6 | 0.142817 | 0.142857 | 4.04e-05 |
| 7 | 0.124915 | 0.125000 | 8.49e-05 |
| 8 | 0.110986 | 0.111111 | 1.25e-04 |
| 9 | 0.099840 | 0.100000 | 1.60e-04 |
| 10 | 0.090719 | 0.090909 | 1.90e-04 |

![spectrum](scripts/cipher_plots/simon32_64.png)

### Simon64/128 (`simon64_128`)

Verdict: PASS &mdash; min p = 0.095 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999966$ bits ($8 - H = 3.43 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.15$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.278 |
| KS vs Uniform(0,1) | 0.342 |
| serial test (pairs, $16 \times 16$ cells) | 0.095 |
| gap test (Knuth, $[0, 1/2)$) | 0.281 |
| permutation test ($d = 4$) | 0.375 |
| cumulative periodogram (Bartlett) | 0.652 |
| runs test (bit stream) | 0.331 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500134 | 0.500000 | 1.34e-04 |
| 2 | 0.333339 | 0.333333 | 5.39e-06 |
| 3 | 0.249914 | 0.250000 | 8.61e-05 |
| 4 | 0.199863 | 0.200000 | 1.37e-04 |
| 5 | 0.166502 | 0.166667 | 1.65e-04 |
| 6 | 0.142678 | 0.142857 | 1.79e-04 |
| 7 | 0.124814 | 0.125000 | 1.86e-04 |
| 8 | 0.110923 | 0.111111 | 1.89e-04 |
| 9 | 0.099812 | 0.100000 | 1.88e-04 |
| 10 | 0.090722 | 0.090909 | 1.87e-04 |

![spectrum](scripts/cipher_plots/simon64_128.png)

### Simon128/128 (`simon128_128`)

Verdict: PASS &mdash; min p = 0.062 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.17 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.49$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.616 |
| KS vs Uniform(0,1) | 0.088 |
| serial test (pairs, $16 \times 16$ cells) | 0.468 |
| gap test (Knuth, $[0, 1/2)$) | 0.109 |
| permutation test ($d = 4$) | 0.413 |
| cumulative periodogram (Bartlett) | 0.714 |
| runs test (bit stream) | 0.062 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499413 | 0.500000 | 5.87e-04 |
| 2 | 0.332645 | 0.333333 | 6.88e-04 |
| 3 | 0.249343 | 0.250000 | 6.57e-04 |
| 4 | 0.199406 | 0.200000 | 5.94e-04 |
| 5 | 0.166138 | 0.166667 | 5.29e-04 |
| 6 | 0.142388 | 0.142857 | 4.69e-04 |
| 7 | 0.124583 | 0.125000 | 4.17e-04 |
| 8 | 0.110740 | 0.111111 | 3.71e-04 |
| 9 | 0.099669 | 0.100000 | 3.31e-04 |
| 10 | 0.090613 | 0.090909 | 2.96e-04 |

![spectrum](scripts/cipher_plots/simon128_128.png)

### Simon128/256 (`simon128_256`)

Verdict: PASS &mdash; min p = 0.087 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999963$ bits ($8 - H = 3.66 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.14$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.087 |
| KS vs Uniform(0,1) | 0.207 |
| serial test (pairs, $16 \times 16$ cells) | 0.331 |
| gap test (Knuth, $[0, 1/2)$) | 0.320 |
| permutation test ($d = 4$) | 0.786 |
| cumulative periodogram (Bartlett) | 0.443 |
| runs test (bit stream) | 0.982 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500630 | 0.500000 | 6.30e-04 |
| 2 | 0.333933 | 0.333333 | 6.00e-04 |
| 3 | 0.250518 | 0.250000 | 5.18e-04 |
| 4 | 0.200437 | 0.200000 | 4.37e-04 |
| 5 | 0.167031 | 0.166667 | 3.65e-04 |
| 6 | 0.143160 | 0.142857 | 3.03e-04 |
| 7 | 0.125251 | 0.125000 | 2.51e-04 |
| 8 | 0.111318 | 0.111111 | 2.06e-04 |
| 9 | 0.100169 | 0.100000 | 1.69e-04 |
| 10 | 0.091045 | 0.090909 | 1.36e-04 |

![spectrum](scripts/cipher_plots/simon128_256.png)

### Speck32/64 (`speck32_64`)

Verdict: PASS &mdash; min p = 0.195 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.20 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 14.60$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.578 |
| KS vs Uniform(0,1) | 0.418 |
| serial test (pairs, $16 \times 16$ cells) | 0.272 |
| gap test (Knuth, $[0, 1/2)$) | 0.917 |
| permutation test ($d = 4$) | 0.358 |
| cumulative periodogram (Bartlett) | 0.195 |
| runs test (bit stream) | 0.370 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499643 | 0.500000 | 3.57e-04 |
| 2 | 0.332859 | 0.333333 | 4.74e-04 |
| 3 | 0.249498 | 0.250000 | 5.02e-04 |
| 4 | 0.199503 | 0.200000 | 4.97e-04 |
| 5 | 0.166186 | 0.166667 | 4.80e-04 |
| 6 | 0.142397 | 0.142857 | 4.60e-04 |
| 7 | 0.124562 | 0.125000 | 4.38e-04 |
| 8 | 0.110694 | 0.111111 | 4.17e-04 |
| 9 | 0.099603 | 0.100000 | 3.97e-04 |
| 10 | 0.090531 | 0.090909 | 3.78e-04 |

![spectrum](scripts/cipher_plots/speck32_64.png)

### Speck64/128 (`speck64_128`)

Verdict: PASS &mdash; min p = 0.119 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999965$ bits ($8 - H = 3.52 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 17.73$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.181 |
| KS vs Uniform(0,1) | 0.635 |
| serial test (pairs, $16 \times 16$ cells) | 0.188 |
| gap test (Knuth, $[0, 1/2)$) | 0.947 |
| permutation test ($d = 4$) | 0.780 |
| cumulative periodogram (Bartlett) | 0.119 |
| runs test (bit stream) | 0.871 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499865 | 0.500000 | 1.35e-04 |
| 2 | 0.333180 | 0.333333 | 1.54e-04 |
| 3 | 0.249844 | 0.250000 | 1.56e-04 |
| 4 | 0.199851 | 0.200000 | 1.49e-04 |
| 5 | 0.166530 | 0.166667 | 1.36e-04 |
| 6 | 0.142735 | 0.142857 | 1.22e-04 |
| 7 | 0.124892 | 0.125000 | 1.08e-04 |
| 8 | 0.111017 | 0.111111 | 9.42e-05 |
| 9 | 0.099918 | 0.100000 | 8.18e-05 |
| 10 | 0.090838 | 0.090909 | 7.06e-05 |

![spectrum](scripts/cipher_plots/speck64_128.png)

### Speck128/128 (`speck128_128`)

Verdict: PASS &mdash; min p = 0.023 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.24 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.58$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.522 |
| KS vs Uniform(0,1) | 0.971 |
| serial test (pairs, $16 \times 16$ cells) | 0.611 |
| gap test (Knuth, $[0, 1/2)$) | 0.025 |
| permutation test ($d = 4$) | 0.805 |
| cumulative periodogram (Bartlett) | 0.023 |
| runs test (bit stream) | 0.984 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500099 | 0.500000 | 9.94e-05 |
| 2 | 0.333409 | 0.333333 | 7.58e-05 |
| 3 | 0.250029 | 0.250000 | 2.95e-05 |
| 4 | 0.199987 | 0.200000 | 1.25e-05 |
| 5 | 0.166621 | 0.166667 | 4.53e-05 |
| 6 | 0.142788 | 0.142857 | 6.93e-05 |
| 7 | 0.124914 | 0.125000 | 8.62e-05 |
| 8 | 0.111013 | 0.111111 | 9.77e-05 |
| 9 | 0.099895 | 0.100000 | 1.05e-04 |
| 10 | 0.090800 | 0.090909 | 1.09e-04 |

![spectrum](scripts/cipher_plots/speck128_128.png)

### Speck128/256 (`speck128_256`)

Verdict: PASS &mdash; min p = 0.639 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.15 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 11.74$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.639 |
| KS vs Uniform(0,1) | 0.899 |
| serial test (pairs, $16 \times 16$ cells) | 0.828 |
| gap test (Knuth, $[0, 1/2)$) | 0.814 |
| permutation test ($d = 4$) | 0.737 |
| cumulative periodogram (Bartlett) | 0.805 |
| runs test (bit stream) | 0.784 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499996 | 0.500000 | 4.25e-06 |
| 2 | 0.333411 | 0.333333 | 7.81e-05 |
| 3 | 0.250131 | 0.250000 | 1.31e-04 |
| 4 | 0.200165 | 0.200000 | 1.65e-04 |
| 5 | 0.166858 | 0.166667 | 1.92e-04 |
| 6 | 0.143071 | 0.142857 | 2.14e-04 |
| 7 | 0.125233 | 0.125000 | 2.33e-04 |
| 8 | 0.111360 | 0.111111 | 2.49e-04 |
| 9 | 0.100263 | 0.100000 | 2.63e-04 |
| 10 | 0.091183 | 0.090909 | 2.74e-04 |

![spectrum](scripts/cipher_plots/speck128_256.png)

### ChaCha20 (`chacha20`)

Verdict: PASS &mdash; min p = 0.073 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.21 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.17$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.555 |
| KS vs Uniform(0,1) | 0.073 |
| serial test (pairs, $16 \times 16$ cells) | 0.631 |
| gap test (Knuth, $[0, 1/2)$) | 0.751 |
| permutation test ($d = 4$) | 0.572 |
| cumulative periodogram (Bartlett) | 0.886 |
| runs test (bit stream) | 0.473 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499556 | 0.500000 | 4.44e-04 |
| 2 | 0.332894 | 0.333333 | 4.39e-04 |
| 3 | 0.249625 | 0.250000 | 3.75e-04 |
| 4 | 0.199690 | 0.200000 | 3.10e-04 |
| 5 | 0.166409 | 0.166667 | 2.58e-04 |
| 6 | 0.142642 | 0.142857 | 2.16e-04 |
| 7 | 0.124819 | 0.125000 | 1.81e-04 |
| 8 | 0.110958 | 0.111111 | 1.53e-04 |
| 9 | 0.099871 | 0.100000 | 1.29e-04 |
| 10 | 0.090800 | 0.090909 | 1.09e-04 |

![spectrum](scripts/cipher_plots/chacha20.png)

### XChaCha20 (`xchacha20`)

Verdict: PASS &mdash; min p = 0.001 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999968$ bits ($8 - H = 3.20 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.91$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.568 |
| KS vs Uniform(0,1) | 0.550 |
| serial test (pairs, $16 \times 16$ cells) | 0.020 |
| gap test (Knuth, $[0, 1/2)$) | 0.924 |
| permutation test ($d = 4$) | 0.001 |
| cumulative periodogram (Bartlett) | 0.901 |
| runs test (bit stream) | 0.791 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499443 | 0.500000 | 5.57e-04 |
| 2 | 0.332775 | 0.333333 | 5.59e-04 |
| 3 | 0.249458 | 0.250000 | 5.42e-04 |
| 4 | 0.199476 | 0.200000 | 5.24e-04 |
| 5 | 0.166161 | 0.166667 | 5.05e-04 |
| 6 | 0.142371 | 0.142857 | 4.86e-04 |
| 7 | 0.124533 | 0.125000 | 4.67e-04 |
| 8 | 0.110663 | 0.111111 | 4.48e-04 |
| 9 | 0.099571 | 0.100000 | 4.29e-04 |
| 10 | 0.090497 | 0.090909 | 4.12e-04 |

![spectrum](scripts/cipher_plots/xchacha20.png)

### Salsa20 (`salsa20`)

Verdict: PASS &mdash; min p = 0.181 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999965$ bits ($8 - H = 3.52 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 14.58$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.181 |
| KS vs Uniform(0,1) | 0.315 |
| serial test (pairs, $16 \times 16$ cells) | 0.703 |
| gap test (Knuth, $[0, 1/2)$) | 0.270 |
| permutation test ($d = 4$) | 0.517 |
| cumulative periodogram (Bartlett) | 0.224 |
| runs test (bit stream) | 0.603 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499635 | 0.500000 | 3.65e-04 |
| 2 | 0.332892 | 0.333333 | 4.41e-04 |
| 3 | 0.249559 | 0.250000 | 4.41e-04 |
| 4 | 0.199587 | 0.200000 | 4.13e-04 |
| 5 | 0.166292 | 0.166667 | 3.74e-04 |
| 6 | 0.142524 | 0.142857 | 3.33e-04 |
| 7 | 0.124707 | 0.125000 | 2.93e-04 |
| 8 | 0.110855 | 0.111111 | 2.56e-04 |
| 9 | 0.099778 | 0.100000 | 2.22e-04 |
| 10 | 0.090718 | 0.090909 | 1.92e-04 |

![spectrum](scripts/cipher_plots/salsa20.png)

### Rabbit (`rabbit`)

Verdict: PASS &mdash; min p = 0.206 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999971$ bits ($8 - H = 2.87 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.42$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.918 |
| KS vs Uniform(0,1) | 0.275 |
| serial test (pairs, $16 \times 16$ cells) | 0.206 |
| gap test (Knuth, $[0, 1/2)$) | 0.306 |
| permutation test ($d = 4$) | 0.425 |
| cumulative periodogram (Bartlett) | 0.238 |
| runs test (bit stream) | 0.926 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.499579 | 0.500000 | 4.21e-04 |
| 2 | 0.332973 | 0.333333 | 3.60e-04 |
| 3 | 0.249673 | 0.250000 | 3.27e-04 |
| 4 | 0.199699 | 0.200000 | 3.01e-04 |
| 5 | 0.166391 | 0.166667 | 2.75e-04 |
| 6 | 0.142605 | 0.142857 | 2.52e-04 |
| 7 | 0.124767 | 0.125000 | 2.33e-04 |
| 8 | 0.110895 | 0.111111 | 2.16e-04 |
| 9 | 0.099797 | 0.100000 | 2.03e-04 |
| 10 | 0.090716 | 0.090909 | 1.93e-04 |

![spectrum](scripts/cipher_plots/rabbit.png)

### ZUC-128 (`zuc128`)

Verdict: PASS &mdash; min p = 0.114 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999964$ bits ($8 - H = 3.61 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 13.54$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.114 |
| KS vs Uniform(0,1) | 0.552 |
| serial test (pairs, $16 \times 16$ cells) | 0.227 |
| gap test (Knuth, $[0, 1/2)$) | 0.265 |
| permutation test ($d = 4$) | 0.551 |
| cumulative periodogram (Bartlett) | 0.623 |
| runs test (bit stream) | 0.166 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500236 | 0.500000 | 2.36e-04 |
| 2 | 0.333560 | 0.333333 | 2.26e-04 |
| 3 | 0.250191 | 0.250000 | 1.91e-04 |
| 4 | 0.200157 | 0.200000 | 1.57e-04 |
| 5 | 0.166798 | 0.166667 | 1.31e-04 |
| 6 | 0.142969 | 0.142857 | 1.12e-04 |
| 7 | 0.125099 | 0.125000 | 9.87e-05 |
| 8 | 0.111200 | 0.111111 | 8.85e-05 |
| 9 | 0.100081 | 0.100000 | 8.06e-05 |
| 10 | 0.090983 | 0.090909 | 7.40e-05 |

![spectrum](scripts/cipher_plots/zuc128.png)

### SNOW 3G (`snow3g`)

Verdict: PASS &mdash; min p = 0.137 against $\alpha / m = 1.43 \times 10^{-4}$; 0 of 7 p-values below $\alpha = 0.001$.

Byte entropy $H = 7.999966$ bits ($8 - H = 3.41 \times 10^{-5}$); 704,810 chunk values; Fisher's $g = 12.74$.

| test | p |
|------|---|
| byte frequency $\chi^2$ (256 cells) | 0.300 |
| KS vs Uniform(0,1) | 0.805 |
| serial test (pairs, $16 \times 16$ cells) | 0.484 |
| gap test (Knuth, $[0, 1/2)$) | 0.423 |
| permutation test ($d = 4$) | 0.597 |
| cumulative periodogram (Bartlett) | 0.165 |
| runs test (bit stream) | 0.137 |

Moments of $u$ (sample, ideal, deviation):

| $k$ | $m_k$ | $1/(k+1)$ | dev |
|-----|-------|-----------|-----|
| 1 | 0.500182 | 0.500000 | 1.82e-04 |
| 2 | 0.333563 | 0.333333 | 2.30e-04 |
| 3 | 0.250236 | 0.250000 | 2.36e-04 |
| 4 | 0.200232 | 0.200000 | 2.32e-04 |
| 5 | 0.166888 | 0.166667 | 2.22e-04 |
| 6 | 0.143065 | 0.142857 | 2.08e-04 |
| 7 | 0.125193 | 0.125000 | 1.93e-04 |
| 8 | 0.111290 | 0.111111 | 1.79e-04 |
| 9 | 0.100165 | 0.100000 | 1.65e-04 |
| 10 | 0.091062 | 0.090909 | 1.53e-04 |

![spectrum](scripts/cipher_plots/snow3g.png)

## Calibration on OS-random streams

The battery ran on 400,000 streams of 5,638,480 bytes each read from `/dev/urandom` (hosts: dennard, twilight; 2026-09-16 01:49 to 2026-09-16 04:37 UTC; mean 4.0 s per stream).  A stream that is random by construction should reject each test with probability $\alpha = 0.001$ and fail the battery with probability at most $\alpha$ if every p-value is valid; the table gives the observed counts with Clopper-Pearson 95% intervals, and the Kolmogorov-Smirnov p-value of each test's 400,000 p-values against Uniform(0,1), which is what a calibrated test produces under the null.

| test | rejections at $\alpha = 0.001$ (rate, 95% CI) | rejections at $\alpha / m = 1.43 \times 10^{-4}$ | KS of p-values vs Uniform(0,1) |
|------|------|------|------|
| byte frequency $\chi^2$ (256 cells) | 422 / 400,000 = 1.05e-03 [9.6e-04, 1.2e-03] | 46 | 0.643 |
| KS vs Uniform(0,1) | 413 / 400,000 = 1.03e-03 [9.4e-04, 1.1e-03] | 60 | 0.406 |
| serial test (pairs, $16 \times 16$ cells) | 399 / 400,000 = 9.97e-04 [9.0e-04, 1.1e-03] | 58 | 0.864 |
| gap test (Knuth, $[0, 1/2)$) | 440 / 400,000 = 1.10e-03 [1.0e-03, 1.2e-03] | 79 | 0.752 |
| permutation test ($d = 4$) | 401 / 400,000 = 1.00e-03 [9.1e-04, 1.1e-03] | 55 | 0.427 |
| cumulative periodogram (Bartlett) | 394 / 400,000 = 9.85e-04 [8.9e-04, 1.1e-03] | 65 | 0.655 |
| runs test (bit stream) | 394 / 400,000 = 9.85e-04 [8.9e-04, 1.1e-03] | 61 | 0.447 |

Battery failures (some $p < \alpha / m$): 419 / 400,000 = 1.05e-03 [9.5e-04, 1.2e-03]; nominal bound $0.001$.
Streams with some $p < \alpha$: 2822 / 400,000 = 7.05e-03 [6.8e-03, 7.3e-03]; nominal bound $m \alpha = 0.007$.

Spearman correlation of the p-values across streams (dependence makes the Bonferroni bound loose, never unsafe, when every p-value is valid):

| | byte_chisq | ks | serial | gap | permutation | bartlett | runs |
|---|---|---|---|---|---|---|---|
| byte_chisq | 1.000 | 0.017 | 0.006 | 0.002 | 0.000 | 0.000 | 0.042 |
| ks | 0.017 | 1.000 | 0.105 | 0.170 | -0.000 | -0.000 | 0.001 |
| serial | 0.006 | 0.105 | 1.000 | 0.023 | 0.030 | 0.021 | 0.003 |
| gap | 0.002 | 0.170 | 0.023 | 1.000 | 0.013 | 0.147 | -0.000 |
| permutation | 0.000 | -0.000 | 0.030 | 0.013 | 1.000 | 0.040 | -0.002 |
| bartlett | 0.000 | -0.000 | 0.021 | 0.147 | 0.040 | 1.000 | 0.000 |
| runs | 0.042 | 0.001 | 0.003 | -0.000 | -0.002 | 0.000 | 1.000 |

Byte entropy over the null streams: mean $8 - H = 3.20 \times 10^{-5}$ bits, sd $4.05 \times 10^{-6}$ bits; the second-order prediction is mean $(K-1)/(2 L \ln 2) = 3.26 \times 10^{-5}$ and sd $\sqrt{2(K-1)}/(2 L \ln 2) = 2.89 \times 10^{-6}$ with $K = 256$.

![calibration](scripts/cipher_plots/calibration.png)

## Held-out calibration at the decision threshold

Predeclared before any held-out stream was drawn (the protocol at `HELD_OUT_STREAMS` in `scripts/cipher_randomness.R`; scripts `17533b1f59585350`): 400,000 fresh streams of 5,638,480 bytes from `/dev/urandom` (hosts dennard, moore), battery version 4 frozen.  At $t = \alpha / m = 1.43 \times 10^{-4}$ a valid p-value has $\Pr(p \le t) \le t$, so each test passes when the one-sided exact binomial test for an excess of rejections over rate $t$ gives at least 0.05 / 7, and the battery passes when the same test of the streams with some $p < t$ against rate $\alpha$ gives at least 0.05.

| test | rejections at $t$ (rate, 95% CI) | expected | excess p | verdict |
|------|------|------|------|------|
| byte frequency $\chi^2$ (256 cells) | 51 / 400,000 = 1.28e-04 [9.5e-05, 1.7e-04] | 57.1 | 0.809 | calibrated |
| KS vs Uniform(0,1) | 62 / 400,000 = 1.55e-04 [1.2e-04, 2.0e-04] | 57.1 | 0.277 | calibrated |
| serial test (pairs, $16 \times 16$ cells) | 56 / 400,000 = 1.40e-04 [1.1e-04, 1.8e-04] | 57.1 | 0.578 | calibrated |
| gap test (Knuth, $[0, 1/2)$) | 57 / 400,000 = 1.42e-04 [1.1e-04, 1.8e-04] | 57.1 | 0.525 | calibrated |
| permutation test ($d = 4$) | 61 / 400,000 = 1.52e-04 [1.2e-04, 2.0e-04] | 57.1 | 0.322 | calibrated |
| cumulative periodogram (Bartlett) | 53 / 400,000 = 1.32e-04 [9.9e-05, 1.7e-04] | 57.1 | 0.726 | calibrated |
| runs test (bit stream) | 60 / 400,000 = 1.50e-04 [1.1e-04, 1.9e-04] | 57.1 | 0.370 | calibrated |

At 400,000 streams the per-test rule flags a count of 77 or more, so a test whose true rejection rate at $t$ is 1.34 times $t$ is flagged only half the time: "calibrated" excludes gross excesses, not small ones.

Battery failures (some $p < t$): 397 / 400,000 = 9.92e-04 [9.0e-04, 1.1e-03] against rate $\alpha = 0.001$ (expected 400.0); excess p 0.566: within the nominal rate.

