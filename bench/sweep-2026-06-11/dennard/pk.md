
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |       19.9 |  ±0.08555 |    50 |
| rsa_encrypt_1024                 |    0.05575 | ±0.0004415 |    50 |
| rsa_decrypt_1024                 |      0.357 | ±0.001737 |    50 |
| rsa_sign_1024                    |     0.3555 | ±0.001777 |    50 |
| rsa_verify_1024                  |    0.05612 | ±0.0002976 |    50 |
| elgamal_keygen_1024              |      100.8 |   ±0.2103 |    50 |
| elgamal_encrypt_1024             |     0.5063 |  ±0.00188 |    50 |
| elgamal_decrypt_1024             |     0.2556 | ±0.002695 |   230 |
| dsa_keygen_1024                  |      72.68 |   ±0.3598 |    50 |
| dsa_sign_1024                    |     0.4909 | ±0.002043 |    50 |
| dsa_verify_1024                  |     0.7115 |  ±0.00235 |    50 |
| paillier_keygen_1024             |      21.81 |  ±0.04013 |   110 |
| paillier_encrypt_1024            |      11.13 |  ±0.01972 |   110 |
| paillier_decrypt_1024            |      3.451 |  ±0.02079 |    50 |
| paillier_rerandomize_1024        |      6.839 |  ±0.02438 |   204 |
| paillier_add_1024                |    0.01774 | ±9.194e-05 |    50 |
| cocks_keygen_1024                |      16.37 |  ±0.03085 |    50 |
| cocks_encrypt_1024               |      1.182 | ±0.002528 |    53 |
| cocks_decrypt_1024               |      0.182 | ±0.001162 |   140 |
| rabin_keygen_1024                |      23.82 |   ±0.0671 |    50 |
| rabin_encrypt_1024               |    0.04895 | ±0.0001563 |    50 |
| rabin_decrypt_1024               |     0.3511 |  ±0.00125 |    82 |
| schmidt_samoa_keygen_1024        |      7.975 |  ±0.02795 |    50 |
| schmidt_samoa_encrypt_1024       |      1.145 |  ±0.00264 |    50 |
| schmidt_samoa_decrypt_1024       |     0.3262 | ±0.002045 |   110 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      348.9 |   ±0.5882 |    50 |
| rsa_encrypt_2048                 |     0.1833 | ±0.000933 |   140 |
| rsa_decrypt_2048                 |      2.148 |  ±0.01567 |    80 |
| rsa_sign_2048                    |       2.13 | ±0.008307 |    53 |
| rsa_verify_2048                  |     0.1822 | ±0.0006971 |   110 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.9807 | ±0.002465 |    80 |
| ecdsa_sign                       |      1.198 | ±0.003238 |    50 |
| ecdsa_verify                     |      2.124 | ±0.004571 |    80 |
| ecdh_keygen                      |     0.9817 | ±0.002259 |    52 |
| ecdh_agree                       |     0.9956 | ±0.001941 |    55 |
| ecdh_serialize                   |  7.902e-05 | ±6.027e-06 |    50 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |     0.9798 | ±0.002046 |    80 |
| ecies_encrypt                    |      1.935 |  ±0.00449 |   110 |
| ecies_decrypt                    |     0.9651 | ±0.002338 |    50 |
| ec_elgamal_keygen                |     0.9807 | ±0.002022 |    83 |
| ec_elgamal_encrypt               |      2.063 | ±0.006264 |    50 |
| ec_elgamal_decrypt               |     0.9947 | ±0.002085 |    52 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.9806 | ±0.002555 |    50 |
| ed25519_sign                     |     0.4994 | ±0.001496 |    50 |
| ed25519_verify                   |      1.649 | ±0.003059 |    50 |
| edwards_dh_keygen                |     0.9571 | ±0.001996 |    80 |
| edwards_dh_agree                 |     0.4804 | ±0.000968 |    80 |
| edwards_dh_serialize             |   5.63e-05 | ±3.284e-06 |    63 |
| edwards_elgamal_keygen           |     0.9579 | ±0.004229 |    50 |
| edwards_elgamal_encrypt          |      1.039 | ±0.002078 |    50 |
| edwards_elgamal_decrypt          |     0.8866 | ±0.002209 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.06611 | ±0.000127 |    50 |
| x25519_agree                     |    0.06476 | ±0.0001436 |   140 |
| x25519_scalar_mult_base          |    0.06482 | ±0.0001382 |    80 |
| x25519_scalar_mult               |    0.06478 | ±0.000105 |    80 |
| x448_keygen                      |     0.3636 | ±0.0004389 |    59 |
| x448_agree                       |     0.3624 | ±0.002268 |    50 |
| x448_scalar_mult_base            |      0.362 | ±0.0006251 |    50 |
| x448_scalar_mult                 |     0.3624 | ±0.0006805 |    89 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.02625 | ±0.001427 |    50 |
| mlkem512_encaps                  |    0.02631 | ±0.0001846 |    50 |
| mlkem512_decaps                  |    0.02972 | ±0.0002383 |   146 |
| mlkem768_keygen                  |    0.04287 | ±0.0003215 |    86 |
| mlkem768_encaps                  |    0.04264 | ±0.0002736 |   269 |
| mlkem768_decaps                  |    0.04735 | ±0.0005021 |   140 |
| mlkem1024_keygen                 |    0.06723 | ±0.000553 |   110 |
| mlkem1024_encaps                 |    0.06504 | ±0.0004139 |   321 |
| mlkem1024_decaps                 |    0.06992 | ±0.0005599 |    50 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.09249 | ±0.0006203 |    51 |
| mldsa44_sign                     |     0.3076 | ±0.001025 |    50 |
| mldsa44_verify                   |     0.0343 | ±0.0003976 |   290 |
| mldsa65_keygen                   |      0.166 | ±0.0008622 |   110 |
| mldsa65_sign                     |     0.5347 | ±0.001611 |    50 |
| mldsa65_verify                   |    0.04925 | ±0.0005806 |   560 |
| mldsa87_keygen                   |     0.2427 | ±0.001139 |    50 |
| mldsa87_sign                     |     0.3393 |  ±0.00139 |    50 |
| mldsa87_verify                   |    0.07421 | ±0.0007654 |    50 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.286 |  ±0.01893 |    50 |
| ntruhps509_encaps                |     0.1075 | ±0.0007177 |   320 |
| ntruhps509_decaps                |     0.1556 | ±0.0008866 |    80 |
| ntruhps677_keygen                |      1.814 |  ±0.01149 |    50 |
| ntruhps677_encaps                |     0.1354 | ±0.0007594 |    50 |
| ntruhps677_decaps                |     0.1634 | ±0.0009009 |    50 |
| ntruhps821_keygen                |      2.854 |  ±0.01281 |    56 |
| ntruhps821_encaps                |     0.1955 | ±0.001349 |    52 |
| ntruhps821_decaps                |     0.2797 | ±0.001448 |    50 |
| ntruhrss701_keygen               |      1.853 |  ±0.04173 |    50 |
| ntruhrss701_encaps               |    0.06868 | ±0.001824 |    50 |
| ntruhrss701_decaps               |       0.17 |   ±0.0009 |    57 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.9514 | ±0.003785 |    50 |
| ntruees401ep1_encrypt            |     0.1126 | ±0.001077 |    59 |
| ntruees401ep1_decrypt            |     0.1591 | ±0.001426 |    56 |
| ntruees443ep1_keygen             |     0.8582 | ±0.002657 |    80 |
| ntruees443ep1_encrypt            |    0.04503 | ±0.0004905 |    50 |
| ntruees443ep1_decrypt            |    0.05064 | ±0.0005347 |    80 |
| ntruees449ep1_keygen             |       1.13 |  ±0.00451 |   200 |
| ntruees449ep1_encrypt            |     0.1588 | ±0.004572 |    50 |
| ntruees449ep1_decrypt            |     0.2007 | ±0.001411 |   115 |
| ntruees541ep1_keygen             |       1.05 | ±0.007288 |    55 |
| ntruees541ep1_encrypt            |    0.07689 | ±0.0008017 |    52 |
| ntruees541ep1_decrypt            |     0.1045 | ±0.0009226 |    50 |
| ntruees677ep1_keygen             |      1.608 | ±0.007254 |    50 |
| ntruees677ep1_encrypt            |     0.2054 | ±0.004011 |    80 |
| ntruees677ep1_decrypt            |     0.3249 | ±0.001881 |    50 |
| ntruees1087ep1_keygen            |      2.661 |  ±0.00826 |    54 |
| ntruees1087ep1_encrypt           |     0.1562 | ±0.001484 |   140 |
| ntruees1087ep1_decrypt           |     0.2263 | ±0.001669 |   114 |
| ntruees1087ep2_keygen            |      2.788 |  ±0.01074 |   140 |
| ntruees1087ep2_encrypt           |     0.2495 | ±0.002322 |    50 |
| ntruees1087ep2_decrypt           |     0.3941 | ±0.002412 |    80 |
| ntruees1171ep1_keygen            |      2.991 |  ±0.01417 |    50 |
| ntruees1171ep1_encrypt           |     0.2388 | ±0.002055 |    80 |
| ntruees1171ep1_decrypt           |     0.3776 | ±0.002803 |    85 |
| ntruees1499ep1_keygen            |       4.35 |  ±0.01322 |    85 |
| ntruees1499ep1_encrypt           |     0.2484 | ±0.002014 |   170 |
| ntruees1499ep1_decrypt           |     0.3927 |  ±0.01566 |    50 |

