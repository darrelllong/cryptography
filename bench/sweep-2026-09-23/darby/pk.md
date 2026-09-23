
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      78.02 |    ±6.467 |    58 |
| rsa_encrypt_1024                 |    0.03154 | ±0.0002848 |    50 |
| rsa_decrypt_1024                 |     0.5258 | ±0.009172 |    50 |
| rsa_sign_1024                    |     0.5262 |   ±0.0092 |    50 |
| rsa_verify_1024                  |    0.03139 | ±0.0007237 |    50 |
| elgamal_keygen_1024              |      138.1 |    ±41.98 |  1246 (limit) |
| elgamal_encrypt_1024             |     0.5708 | ±0.000619 |    50 |
| elgamal_decrypt_1024             |     0.5731 |  ±0.01032 |    50 |
| dsa_keygen_1024                  |      113.2 |    ±39.81 |   846 (limit) |
| dsa_sign_1024                    |     0.3003 | ±0.007496 |    50 |
| dsa_verify_1024                  |     0.5704 | ±0.002527 |    50 |
| paillier_keygen_1024             |      66.44 |    ±2.277 |    50 |
| paillier_encrypt_1024            |      8.197 |  ±0.01224 |    50 |
| paillier_decrypt_1024            |      6.495 |   ±0.1452 |    50 |
| paillier_rerandomize_1024        |      6.507 |  ±0.03778 |    50 |
| paillier_add_1024                |    0.02199 | ±1.504e-05 |    50 |
| cocks_keygen_1024                |      58.91 |    ±2.158 |    53 |
| cocks_encrypt_1024               |      1.728 | ±0.008464 |    81 |
| cocks_decrypt_1024               |     0.2451 | ±0.002449 |    50 |
| rabin_keygen_1024                |      83.28 |    ±4.887 |    50 |
| rabin_encrypt_1024               |   0.007997 | ±0.0001763 |    50 |
| rabin_decrypt_1024               |     0.5143 | ±0.003178 |    50 |
| schmidt_samoa_keygen_1024        |       22.7 |   ±0.8077 |    50 |
| schmidt_samoa_encrypt_1024       |      1.725 |  ±0.01839 |    50 |
| schmidt_samoa_decrypt_1024       |     0.5675 |  ±0.00604 |    80 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |        691 |    ±119.2 |   429 (limit) |
| rsa_encrypt_2048                 |     0.1086 | ±9.326e-05 |    54 |
| rsa_decrypt_2048                 |      3.561 | ±0.003652 |    80 |
| rsa_sign_2048                    |      3.562 | ±0.004348 |   110 |
| rsa_verify_2048                  |     0.1078 |  ±0.00189 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      1.465 |  ±0.02015 |    50 |
| ecdsa_sign                       |      1.469 |  ±0.02007 |    50 |
| ecdsa_verify                     |      2.955 |  ±0.02072 |    50 |
| ecdh_keygen                      |      1.472 |  ±0.03269 |   110 |
| ecdh_agree                       |      1.462 |  ±0.02605 |    50 |
| ecdh_serialize                   |  0.0002313 | ±8.316e-06 |    50 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.459 | ±0.008326 |    50 |
| ecies_encrypt                    |      2.919 |  ±0.02731 |    50 |
| ecies_decrypt                    |      1.468 |  ±0.02101 |    80 |
| ec_elgamal_keygen                |      1.469 |  ±0.02781 |    50 |
| ec_elgamal_encrypt               |      4.446 |  ±0.08005 |    80 |
| ec_elgamal_decrypt               |      4.288 |  ±0.03864 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.1437 | ±2.657e-05 |    80 |
| ed25519_sign                     |     0.1134 | ±2.911e-05 |   111 |
| ed25519_verify                   |      1.994 |  ±0.02242 |    51 |
| edwards_dh_keygen                |      1.668 |  ±0.01875 |    80 |
| edwards_dh_agree                 |     0.8353 | ±0.007101 |   115 |
| edwards_dh_serialize             |  6.664e-05 | ±8.715e-07 |    50 |
| edwards_elgamal_keygen           |      1.667 |  ±0.02915 |    50 |
| edwards_elgamal_encrypt          |      1.779 |  ±0.03171 |    50 |
| edwards_elgamal_decrypt          |      1.396 |  ±0.01269 |   110 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |     0.2751 | ±0.001621 |    50 |
| x25519_agree                     |     0.2746 | ±0.002523 |    80 |
| x25519_scalar_mult_base          |     0.2746 | ±0.002842 |    50 |
| x25519_scalar_mult               |     0.2737 | ±0.0001899 |    50 |
| x448_keygen                      |      1.075 |  ±0.01259 |    50 |
| x448_agree                       |      1.073 | ±0.009877 |    50 |
| x448_scalar_mult_base            |      1.073 |  ±0.01137 |    50 |
| x448_scalar_mult                 |       1.07 | ±0.0001462 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |     0.2696 | ±0.0001931 |    56 |
| mlkem512_encaps                  |    0.06037 | ±0.0001224 |    53 |
| mlkem512_decaps                  |    0.07534 | ±0.0001802 |    50 |
| mlkem768_keygen                  |     0.4284 | ±0.0002585 |    80 |
| mlkem768_encaps                  |    0.08017 | ±0.0002799 |   140 |
| mlkem768_decaps                  |     0.1003 | ±0.0002737 |    50 |
| mlkem1024_keygen                 |     0.6472 | ±0.0005389 |    50 |
| mlkem1024_encaps                 |     0.1401 | ±0.0002869 |   650 |
| mlkem1024_decaps                 |     0.1742 | ±0.0002492 |   350 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.2159 | ±0.0003011 |   170 |
| mldsa44_sign                     |     0.7351 |   ±0.0262 |    80 |
| mldsa44_verify                   |    0.07612 | ±0.0001944 |    80 |
| mldsa65_keygen                   |     0.3832 | ±0.0005827 |    80 |
| mldsa65_sign                     |      1.137 |  ±0.05826 |    50 |
| mldsa65_verify                   |     0.1057 | ±0.0002935 |   170 |
| mldsa87_keygen                   |     0.6105 | ±0.001038 |    50 |
| mldsa87_sign                     |      1.205 |  ±0.07201 |   140 |
| mldsa87_verify                   |     0.1548 | ±0.0004587 |    50 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      3.687 |  ±0.01718 |    51 |
| ntruhps509_encaps                |     0.1435 | ±0.0004002 |   111 |
| ntruhps509_decaps                |     0.2581 | ±0.0008863 |    50 |
| ntruhps677_keygen                |      3.333 | ±0.0007429 |    50 |
| ntruhps677_encaps                |     0.1918 | ±0.0003838 |    51 |
| ntruhps677_decaps                |     0.2592 | ±0.0003085 |    50 |
| ntruhps821_keygen                |      5.996 |  ±0.04383 |    88 |
| ntruhps821_encaps                |     0.2559 | ±0.0003846 |    88 |
| ntruhps821_decaps                |     0.4356 | ±0.001669 |    80 |
| ntruhrss701_keygen               |      4.039 | ±0.004182 |    50 |
| ntruhrss701_encaps               |     0.1249 | ±0.0002793 |   140 |
| ntruhrss701_decaps               |     0.3001 | ±0.000266 |   140 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.8422 | ±0.001308 |    84 |
| ntruees401ep1_encrypt            |     0.1721 | ±0.004166 |   110 |
| ntruees401ep1_decrypt            |     0.2877 | ±0.0007025 |    80 |
| ntruees443ep1_keygen             |     0.8698 | ±0.001288 |    50 |
| ntruees443ep1_encrypt            |    0.04818 | ±0.0003522 |    50 |
| ntruees443ep1_decrypt            |    0.07583 | ±0.0004121 |   110 |
| ntruees449ep1_keygen             |      1.049 | ±0.001323 |    80 |
| ntruees449ep1_encrypt            |     0.3283 |  ±0.01846 |   110 |
| ntruees449ep1_decrypt            |     0.4834 | ±0.004274 |    50 |
| ntruees541ep1_keygen             |     0.9682 | ±0.001963 |    50 |
| ntruees541ep1_encrypt            |     0.1372 | ±0.0005541 |  1190 |
| ntruees541ep1_decrypt            |     0.1773 | ±0.0009429 |   140 |
| ntruees677ep1_keygen             |      1.436 | ±0.002582 |    50 |
| ntruees677ep1_encrypt            |     0.3516 | ±0.0007137 |   170 |
| ntruees677ep1_decrypt            |     0.6386 | ±0.002021 |    54 |
| ntruees1087ep1_keygen            |      1.806 | ±0.002265 |    50 |
| ntruees1087ep1_encrypt           |     0.2243 | ±0.001729 |    50 |
| ntruees1087ep1_decrypt           |     0.4262 | ±0.001189 |    50 |
| ntruees1087ep2_keygen            |      1.898 | ±0.002775 |    50 |
| ntruees1087ep2_encrypt           |     0.3984 | ±0.002388 |    53 |
| ntruees1087ep2_decrypt           |     0.7852 | ±0.001884 |    54 |
| ntruees1171ep1_keygen            |      2.262 | ±0.003696 |    80 |
| ntruees1171ep1_encrypt           |     0.5076 |  ±0.00466 |   209 |
| ntruees1171ep1_decrypt           |      0.746 | ±0.003099 |   110 |
| ntruees1499ep1_keygen            |      4.252 | ±0.004143 |    50 |
| ntruees1499ep1_encrypt           |     0.3812 | ±0.003605 |    50 |
| ntruees1499ep1_decrypt           |     0.6977 | ±0.002565 |   110 |

