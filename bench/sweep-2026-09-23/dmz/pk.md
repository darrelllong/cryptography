
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |       40.9 |    ±3.391 |   233 |
| rsa_encrypt_1024                 |    0.01606 | ±0.0001123 |    50 |
| rsa_decrypt_1024                 |      0.269 | ±0.001704 |    50 |
| rsa_sign_1024                    |      0.269 | ±0.0008321 |    80 |
| rsa_verify_1024                  |    0.01617 | ±0.0006315 |    50 |
| elgamal_keygen_1024              |      49.22 |    ±12.43 |  2508 (limit) |
| elgamal_encrypt_1024             |     0.2687 | ±0.002208 |   118 |
| elgamal_decrypt_1024             |     0.2669 | ±0.002072 |    50 |
| dsa_keygen_1024                  |      61.84 |    ±13.44 |  1633 (limit) |
| dsa_sign_1024                    |     0.1485 | ±0.008195 |    80 |
| dsa_verify_1024                  |     0.2686 | ±0.001634 |   140 |
| paillier_keygen_1024             |      35.66 |    ±1.521 |   142 |
| paillier_encrypt_1024            |      3.733 |  ±0.01289 |    81 |
| paillier_decrypt_1024            |      2.928 |  ±0.01117 |    50 |
| paillier_rerandomize_1024        |       2.95 |  ±0.00805 |   140 |
| paillier_add_1024                |   0.008569 | ±8.084e-05 |    50 |
| cocks_keygen_1024                |      32.45 |    ±1.564 |    80 |
| cocks_encrypt_1024               |     0.8102 | ±0.001688 |    50 |
| cocks_decrypt_1024               |     0.1252 | ±0.0004733 |    50 |
| rabin_keygen_1024                |      42.35 |    ±2.859 |    50 |
| rabin_encrypt_1024               |   0.004385 | ±4.149e-05 |    87 |
| rabin_decrypt_1024               |     0.2613 | ±0.0006882 |    55 |
| schmidt_samoa_keygen_1024        |      13.22 |   ±0.4485 |    50 |
| schmidt_samoa_encrypt_1024       |     0.8147 | ±0.004449 |    50 |
| schmidt_samoa_decrypt_1024       |     0.2826 | ±0.001335 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |        348 |    ±71.47 |   877 (limit) |
| rsa_encrypt_2048                 |    0.05223 | ±0.0003569 |    50 |
| rsa_decrypt_2048                 |      1.669 | ±0.005111 |    50 |
| rsa_sign_2048                    |      1.668 | ±0.004323 |    81 |
| rsa_verify_2048                  |    0.05164 | ±0.0004909 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.9903 |  ±0.02742 |    50 |
| ecdsa_sign                       |     0.9984 |  ±0.02286 |    87 |
| ecdsa_verify                     |      2.005 |  ±0.04739 |    87 |
| ecdh_keygen                      |     0.9819 | ±0.002877 |    50 |
| ecdh_agree                       |     0.9742 | ±0.005838 |    50 |
| ecdh_serialize                   |  0.0001995 | ±7.049e-06 |    80 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |     0.9825 | ±0.002926 |    50 |
| ecies_encrypt                    |      1.965 |  ±0.04758 |    50 |
| ecies_decrypt                    |      0.982 | ±0.005886 |    50 |
| ec_elgamal_keygen                |     0.9935 |  ±0.02653 |    50 |
| ec_elgamal_encrypt               |      2.953 |  ±0.01125 |    50 |
| ec_elgamal_decrypt               |      2.887 |  ±0.01002 |    53 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |    0.04652 | ±0.0002407 |    86 |
| ed25519_sign                     |    0.03852 | ±0.0003615 |   110 |
| ed25519_verify                   |      1.142 | ±0.006302 |    50 |
| edwards_dh_keygen                |     0.9427 | ±0.005078 |   260 |
| edwards_dh_agree                 |     0.4694 |  ±0.00233 |    52 |
| edwards_dh_serialize             |  5.965e-05 | ±4.972e-06 |    63 |
| edwards_elgamal_keygen           |      0.943 | ±0.005946 |    50 |
| edwards_elgamal_encrypt          |          1 | ±0.004933 |    51 |
| edwards_elgamal_decrypt          |     0.8059 | ±0.003624 |   115 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.06875 |  ±0.00034 |    50 |
| x25519_agree                     |    0.06781 | ±0.0005947 |   170 |
| x25519_scalar_mult_base          |    0.06795 | ±0.0003087 |    50 |
| x25519_scalar_mult               |    0.06791 | ±0.0002302 |    52 |
| x448_keygen                      |     0.4236 | ±0.001496 |   140 |
| x448_agree                       |     0.4229 |  ±0.00256 |    54 |
| x448_scalar_mult_base            |      0.421 | ±0.001215 |    50 |
| x448_scalar_mult                 |      0.422 | ±0.001711 |   114 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |     0.1903 | ±0.0007349 |    50 |
| mlkem512_encaps                  |    0.04297 | ±0.0002806 |    80 |
| mlkem512_decaps                  |    0.06612 | ±0.0002058 |    50 |
| mlkem768_keygen                  |     0.3038 | ±0.003182 |   320 |
| mlkem768_encaps                  |     0.0585 | ±0.0001924 |    50 |
| mlkem768_decaps                  |    0.07493 | ±0.0001875 |    50 |
| mlkem1024_keygen                 |     0.4611 | ±0.002136 |    50 |
| mlkem1024_encaps                 |    0.08018 | ±0.0003766 |    50 |
| mlkem1024_decaps                 |      0.103 | ±0.0005815 |    80 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.1497 | ±0.0001907 |    80 |
| mldsa44_sign                     |     0.4678 |  ±0.01832 |    50 |
| mldsa44_verify                   |    0.05404 | ±0.001635 |    50 |
| mldsa65_keygen                   |     0.2592 | ±0.001798 |    50 |
| mldsa65_sign                     |     0.7417 |  ±0.03812 |    50 |
| mldsa65_verify                   |    0.07565 | ±0.0007925 |    50 |
| mldsa87_keygen                   |     0.4043 | ±0.002247 |    82 |
| mldsa87_sign                     |     0.7784 |  ±0.04432 |    50 |
| mldsa87_verify                   |     0.1105 | ±0.0008294 |   170 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.985 | ±0.007794 |    54 |
| ntruhps509_encaps                |    0.09892 | ±0.001453 |    50 |
| ntruhps509_decaps                |     0.1476 | ±0.001305 |    50 |
| ntruhps677_keygen                |      2.106 |  ±0.01404 |   170 |
| ntruhps677_encaps                |     0.1428 | ±0.0004527 |   290 |
| ntruhps677_decaps                |     0.1725 | ±0.0004538 |   384 |
| ntruhps821_keygen                |      3.534 |  ±0.01639 |   140 |
| ntruhps821_encaps                |     0.1828 | ±0.001508 |    50 |
| ntruhps821_decaps                |     0.2654 | ±0.001688 |   320 |
| ntruhrss701_keygen               |      2.463 |   ±0.0361 |    50 |
| ntruhrss701_encaps               |     0.0848 | ±0.0002346 |   170 |
| ntruhrss701_decaps               |     0.1888 | ±0.001923 |    80 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.6862 | ±0.009507 |    50 |
| ntruees401ep1_encrypt            |      0.123 | ±0.003807 |    50 |
| ntruees401ep1_decrypt            |     0.2627 | ±0.002082 |    50 |
| ntruees443ep1_keygen             |     0.6431 | ±0.005997 |   140 |
| ntruees443ep1_encrypt            |     0.0371 | ±0.001287 |    50 |
| ntruees443ep1_decrypt            |    0.06381 | ±0.0007183 |    50 |
| ntruees449ep1_keygen             |     0.8039 | ±0.009526 |   170 |
| ntruees449ep1_encrypt            |     0.1749 |   ±0.0108 |    50 |
| ntruees449ep1_decrypt            |     0.2982 | ±0.002646 |   170 |
| ntruees541ep1_keygen             |     0.6848 | ±0.003055 |   110 |
| ntruees541ep1_encrypt            |    0.08018 | ±0.0003181 |   261 |
| ntruees541ep1_decrypt            |     0.1767 | ±0.001055 |    50 |
| ntruees677ep1_keygen             |       1.16 |  ±0.01764 |    80 |
| ntruees677ep1_encrypt            |     0.2966 | ±0.0008333 |   147 |
| ntruees677ep1_decrypt            |     0.5778 | ±0.003554 |   170 |
| ntruees1087ep1_keygen            |      1.601 |  ±0.01037 |    55 |
| ntruees1087ep1_encrypt           |     0.1937 | ±0.001784 |    50 |
| ntruees1087ep1_decrypt           |     0.4014 |  ±0.00271 |    50 |
| ntruees1087ep2_keygen            |      1.706 | ±0.009348 |    57 |
| ntruees1087ep2_encrypt           |     0.3466 | ±0.003217 |    50 |
| ntruees1087ep2_decrypt           |     0.7216 | ±0.004442 |    50 |
| ntruees1171ep1_keygen            |       1.88 | ±0.009146 |   260 |
| ntruees1171ep1_encrypt           |     0.3326 |  ±0.00613 |   233 |
| ntruees1171ep1_decrypt           |     0.6731 | ±0.007716 |    51 |
| ntruees1499ep1_keygen            |      2.946 |  ±0.01247 |    81 |
| ntruees1499ep1_encrypt           |     0.3224 | ±0.006454 |    50 |
| ntruees1499ep1_decrypt           |     0.5404 | ±0.003417 |    50 |

