
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      33.88 |   ±0.2258 |    50 |
| rsa_encrypt_1024                 |     0.0877 | ±0.0001326 |    80 |
| rsa_decrypt_1024                 |     0.6029 | ±0.001441 |    54 |
| rsa_sign_1024                    |     0.6034 | ±0.004429 |   110 |
| rsa_verify_1024                  |    0.08828 | ±0.0001398 |    50 |
| elgamal_keygen_1024              |      184.3 |   ±0.3292 |    50 |
| elgamal_encrypt_1024             |     0.9358 | ±0.002231 |    50 |
| elgamal_decrypt_1024             |     0.4684 | ±0.001309 |    50 |
| dsa_keygen_1024                  |      132.6 |   ±0.1653 |    50 |
| dsa_sign_1024                    |     0.7664 | ±0.001069 |   140 |
| dsa_verify_1024                  |       1.19 | ±0.001214 |    50 |
| paillier_keygen_1024             |      37.31 |  ±0.09352 |    50 |
| paillier_encrypt_1024            |      16.83 |  ±0.02888 |    50 |
| paillier_decrypt_1024            |      6.756 | ±0.009089 |    50 |
| paillier_rerandomize_1024        |      10.88 | ±0.007022 |    50 |
| paillier_add_1024                |    0.03443 | ±0.0001233 |    50 |
| cocks_keygen_1024                |      28.01 |   ±0.1047 |    50 |
| cocks_encrypt_1024               |      2.109 | ±0.002534 |    51 |
| cocks_decrypt_1024               |     0.3033 | ±0.0005293 |    53 |
| rabin_keygen_1024                |      40.07 |  ±0.06199 |    54 |
| rabin_encrypt_1024               |    0.07194 | ±0.000127 |    80 |
| rabin_decrypt_1024               |     0.5997 | ±0.001361 |    50 |
| schmidt_samoa_keygen_1024        |      12.99 |    ±0.114 |    50 |
| schmidt_samoa_encrypt_1024       |      2.067 | ±0.003364 |    55 |
| schmidt_samoa_decrypt_1024       |     0.5726 | ±0.001435 |   115 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      634.8 |   ±0.5187 |    50 |
| rsa_encrypt_2048                 |     0.3194 | ±0.0002187 |    50 |
| rsa_decrypt_2048                 |      3.921 | ±0.006826 |    50 |
| rsa_sign_2048                    |      3.902 | ±0.004521 |    50 |
| rsa_verify_2048                  |       0.32 | ±0.0005687 |    85 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      1.385 | ±0.005446 |    50 |
| ecdsa_sign                       |      1.666 | ±0.005926 |   170 |
| ecdsa_verify                     |       2.97 | ±0.005449 |    50 |
| ecdh_keygen                      |      1.385 | ±0.002536 |   140 |
| ecdh_agree                       |      1.404 | ±0.003535 |    50 |
| ecdh_serialize                   |  0.0001935 | ±1.602e-05 |  5453 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.383 | ±0.003585 |    50 |
| ecies_encrypt                    |      2.726 | ±0.003517 |    80 |
| ecies_decrypt                    |      1.374 | ±0.004269 |    50 |
| ec_elgamal_keygen                |      1.383 | ±0.002287 |    80 |
| ec_elgamal_encrypt               |      2.914 | ±0.004956 |    50 |
| ec_elgamal_decrypt               |       1.42 | ±0.006162 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      1.395 | ±0.002799 |    80 |
| ed25519_sign                     |     0.7129 | ±0.002602 |    50 |
| ed25519_verify                   |      2.309 | ±0.002986 |    50 |
| edwards_dh_keygen                |      1.362 | ±0.002001 |    50 |
| edwards_dh_agree                 |     0.6853 | ±0.003272 |    50 |
| edwards_dh_serialize             |  8.606e-05 | ±6.059e-06 | 26406 |
| edwards_elgamal_keygen           |      1.362 | ±0.002431 |    80 |
| edwards_elgamal_encrypt          |      1.484 | ±0.004715 |    53 |
| edwards_elgamal_decrypt          |      1.288 | ±0.004933 |    80 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.09801 | ±0.0008463 |   114 |
| x25519_agree                     |    0.09582 | ±0.0009545 |    50 |
| x25519_scalar_mult_base          |    0.09562 | ±0.001203 |    50 |
| x25519_scalar_mult               |    0.09611 | ±0.001044 |    50 |
| x448_keygen                      |     0.6115 | ±0.004997 |    82 |
| x448_agree                       |     0.6086 | ±0.003368 |   119 |
| x448_scalar_mult_base            |     0.6096 |  ±0.00517 |    50 |
| x448_scalar_mult                 |       0.61 | ±0.004709 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.04501 | ±0.003714 |  7431 |
| mlkem512_encaps                  |    0.04929 |  ±0.00411 |  6860 |
| mlkem512_decaps                  |    0.04696 | ±0.003221 | 24920 |
| mlkem768_keygen                  |    0.08338 | ±0.006911 |  7229 |
| mlkem768_encaps                  |    0.07825 | ±0.006517 |  7319 |
| mlkem768_decaps                  |    0.08243 | ±0.006862 |  7735 |
| mlkem1024_keygen                 |     0.1221 | ±0.008786 |  5360 |
| mlkem1024_encaps                 |     0.1197 | ±0.009962 |  9802 |
| mlkem1024_decaps                 |     0.1257 |  ±0.01048 |  8098 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.1715 |  ±0.01414 |  1193 |
| mldsa44_sign                     |     0.4643 |  ±0.02961 |    80 |
| mldsa44_verify                   |      0.061 | ±0.005034 | 10492 |
| mldsa65_keygen                   |     0.2937 |  ±0.02395 |   146 |
| mldsa65_sign                     |      0.808 |  ±0.05505 |    50 |
| mldsa65_verify                   |    0.07582 | ±0.006299 | 26724 |
| mldsa87_keygen                   |     0.4167 |  ±0.03345 |    80 |
| mldsa87_sign                     |     0.5381 |  ±0.04437 |    87 |
| mldsa87_verify                   |     0.1129 | ±0.007483 | 27380 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      2.629 |  ±0.02699 |    50 |
| ntruhps509_encaps                |     0.2244 |  ±0.01842 |    59 |
| ntruhps509_decaps                |     0.3515 |  ±0.02485 |    50 |
| ntruhps677_keygen                |       3.55 |   ±0.0335 |    53 |
| ntruhps677_encaps                |     0.2614 |  ±0.01821 |    80 |
| ntruhps677_decaps                |     0.3451 |  ±0.02874 |    86 |
| ntruhps821_keygen                |      5.789 |   ±0.0654 |    50 |
| ntruhps821_encaps                |     0.3838 |  ±0.02866 |    50 |
| ntruhps821_decaps                |     0.5933 |  ±0.04776 |    50 |
| ntruhrss701_keygen               |      3.965 |  ±0.03582 |    83 |
| ntruhrss701_encaps               |     0.1479 | ±0.009721 |    80 |
| ntruhrss701_decaps               |     0.3736 |  ±0.01242 |    51 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |      1.904 |   ±0.1461 |    53 |
| ntruees401ep1_encrypt            |     0.3134 |  ±0.02604 |   269 |
| ntruees401ep1_decrypt            |      0.482 |  ±0.03502 |    50 |
| ntruees443ep1_keygen             |      1.705 |   ±0.0488 |    50 |
| ntruees443ep1_encrypt            |    0.09918 | ±0.006305 | 32600 |
| ntruees443ep1_decrypt            |      0.138 |  ±0.01099 |  2780 |
| ntruees449ep1_keygen             |       2.36 |   ±0.1519 |    50 |
| ntruees449ep1_encrypt            |     0.4487 |  ±0.03735 |    50 |
| ntruees449ep1_decrypt            |     0.6183 |  ±0.04357 |    88 |
| ntruees541ep1_keygen             |      2.016 |   ±0.1354 |    50 |
| ntruees541ep1_encrypt            |     0.2005 |  ±0.01662 |  7258 |
| ntruees541ep1_decrypt            |     0.3106 |  ±0.02562 |   172 |
| ntruees677ep1_keygen             |      3.182 |  ±0.07315 |    80 |
| ntruees677ep1_encrypt            |     0.5881 |  ±0.03067 |    50 |
| ntruees677ep1_decrypt            |      1.047 |  ±0.08623 |    50 |
| ntruees1087ep1_keygen            |       4.91 |  ±0.08407 |    81 |
| ntruees1087ep1_encrypt           |     0.4486 |  ±0.03395 |    50 |
| ntruees1087ep1_decrypt           |     0.7641 |  ±0.05133 |    50 |
| ntruees1087ep2_keygen            |      5.184 |   ±0.2943 |    50 |
| ntruees1087ep2_encrypt           |     0.7646 |  ±0.02878 |   112 |
| ntruees1087ep2_decrypt           |      1.388 |   ±0.1139 |    55 |
| ntruees1171ep1_keygen            |      6.048 |   ±0.4397 |    50 |
| ntruees1171ep1_encrypt           |     0.7332 |  ±0.05119 |    50 |
| ntruees1171ep1_decrypt           |      1.308 |  ±0.09014 |    50 |
| ntruees1499ep1_keygen            |      9.092 |   ±0.1852 |   110 |
| ntruees1499ep1_encrypt           |     0.7275 |  ±0.05999 |    59 |
| ntruees1499ep1_decrypt           |       1.24 |  ±0.03257 |    50 |

