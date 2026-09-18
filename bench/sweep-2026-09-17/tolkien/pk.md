
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      33.53 |    ±2.681 |    50 |
| rsa_encrypt_1024                 |    0.01209 | ±2.697e-05 |   144 |
| rsa_decrypt_1024                 |     0.2277 | ±0.0005103 |    50 |
| rsa_sign_1024                    |     0.2272 | ±0.0005024 |    50 |
| rsa_verify_1024                  |     0.0119 | ±3.212e-05 |   111 |
| elgamal_keygen_1024              |      38.74 |    ±8.091 |  3638 (limit) |
| elgamal_encrypt_1024             |     0.1794 | ±0.0002359 |    50 |
| elgamal_decrypt_1024             |     0.1749 | ±0.0005056 |    50 |
| dsa_keygen_1024                  |      39.53 |    ±9.132 |  2504 (limit) |
| dsa_sign_1024                    |    0.09978 | ±0.002102 |    52 |
| dsa_verify_1024                  |     0.1762 | ±0.0006772 |    50 |
| paillier_keygen_1024             |      28.12 |     ±0.92 |    57 |
| paillier_encrypt_1024            |      2.445 | ±0.003191 |    80 |
| paillier_decrypt_1024            |      1.915 |  ±0.01385 |    50 |
| paillier_rerandomize_1024        |      1.937 | ±0.005928 |    50 |
| paillier_add_1024                |   0.006452 | ±6.372e-06 |    50 |
| cocks_keygen_1024                |      25.65 |    ±1.018 |    50 |
| cocks_encrypt_1024               |     0.5342 | ±0.001066 |    51 |
| cocks_decrypt_1024               |     0.1066 | ±0.0003514 |    50 |
| rabin_keygen_1024                |      36.89 |    ±2.782 |    80 |
| rabin_encrypt_1024               |   0.003374 | ±1.705e-05 |    50 |
| rabin_decrypt_1024               |     0.2215 | ±0.0004683 |    50 |
| schmidt_samoa_keygen_1024        |      10.29 |   ±0.3408 |    56 |
| schmidt_samoa_encrypt_1024       |     0.5405 |   ±0.0104 |    84 |
| schmidt_samoa_decrypt_1024       |     0.1903 | ±0.006931 |    80 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      206.3 |    ±40.91 |  1350 (limit) |
| rsa_encrypt_2048                 |    0.03688 | ±0.0004508 |   148 |
| rsa_decrypt_2048                 |      1.121 |  ±0.00151 |    80 |
| rsa_sign_2048                    |       1.12 | ±0.001555 |    50 |
| rsa_verify_2048                  |     0.0362 | ±0.0004882 |    80 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      0.837 | ±0.0007773 |   140 |
| ecdsa_sign                       |     0.8465 | ±0.002616 |    80 |
| ecdsa_verify                     |      1.691 | ±0.009689 |    50 |
| ecdh_keygen                      |     0.8375 | ±0.001055 |    50 |
| ecdh_agree                       |     0.8315 | ±0.002594 |    80 |
| ecdh_serialize                   |  0.0001858 | ±9.469e-07 |   148 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |     0.8373 | ±0.0009133 |   110 |
| ecies_encrypt                    |      1.668 | ±0.002696 |   173 |
| ecies_decrypt                    |     0.8392 | ±0.009481 |    50 |
| ec_elgamal_keygen                |     0.8376 | ±0.001266 |    50 |
| ec_elgamal_encrypt               |      2.528 | ±0.008849 |    80 |
| ec_elgamal_decrypt               |      2.472 |  ±0.01183 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.4515 | ±0.0004833 |    50 |
| ed25519_sign                     |     0.4482 | ±0.001666 |   140 |
| ed25519_verify                   |      1.058 | ±0.007348 |   140 |
| edwards_dh_keygen                |     0.8855 | ±0.001035 |    50 |
| edwards_dh_agree                 |     0.4459 | ±0.001948 |    50 |
| edwards_dh_serialize             |   4.33e-05 | ±1.548e-06 |    50 |
| edwards_elgamal_keygen           |      0.885 | ±0.0008794 |    80 |
| edwards_elgamal_encrypt          |     0.9495 | ±0.007062 |    50 |
| edwards_elgamal_decrypt          |     0.7323 | ±0.0009783 |    80 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.03554 | ±2.514e-06 |    80 |
| x25519_agree                     |      0.035 | ±2.191e-06 |   110 |
| x25519_scalar_mult_base          |      0.035 | ±2.879e-06 |    80 |
| x25519_scalar_mult               |      0.035 | ±2.551e-06 |    89 |
| x448_keygen                      |     0.2325 | ±4.865e-05 |    80 |
| x448_agree                       |     0.2318 | ±4.624e-05 |    80 |
| x448_scalar_mult_base            |     0.2318 | ±3.627e-05 |   110 |
| x448_scalar_mult                 |     0.2319 | ±8.278e-05 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.08829 | ±6.326e-05 |    83 |
| mlkem512_encaps                  |    0.01885 | ±7.105e-06 |    89 |
| mlkem512_decaps                  |    0.02376 | ±1.705e-05 |    80 |
| mlkem768_keygen                  |       0.14 | ±0.0001843 |   110 |
| mlkem768_encaps                  |    0.02455 | ±9.881e-06 |   200 |
| mlkem768_decaps                  |    0.03113 | ±1.166e-05 |   111 |
| mlkem1024_keygen                 |     0.2111 | ±0.0001812 |    80 |
| mlkem1024_encaps                 |    0.03195 | ±1.619e-05 |   238 |
| mlkem1024_decaps                 |     0.0405 | ±2.208e-05 |    80 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.06244 | ±5.137e-05 |    55 |
| mldsa44_sign                     |     0.1838 | ±0.006897 |    50 |
| mldsa44_verify                   |    0.02118 | ±2.543e-05 |    80 |
| mldsa65_keygen                   |     0.1159 | ±9.602e-05 |    80 |
| mldsa65_sign                     |     0.2902 |  ±0.01529 |    81 |
| mldsa65_verify                   |    0.02918 | ±2.876e-05 |   170 |
| mldsa87_keygen                   |     0.1693 | ±0.0001286 |   140 |
| mldsa87_sign                     |     0.3039 |  ±0.01665 |    50 |
| mldsa87_verify                   |    0.04249 | ±5.373e-05 |    80 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.899 | ±0.001022 |    50 |
| ntruhps509_encaps                |    0.07319 | ±4.764e-05 |    80 |
| ntruhps509_decaps                |     0.1285 | ±8.205e-05 |    50 |
| ntruhps677_keygen                |      1.227 | ±0.001081 |    58 |
| ntruhps677_encaps                |    0.08563 | ±8.291e-05 |   290 |
| ntruhps677_decaps                |    0.09114 | ±9.64e-05 |    80 |
| ntruhps821_keygen                |      3.629 |  ±0.00147 |    50 |
| ntruhps821_encaps                |      0.144 | ±7.791e-05 |  1161 |
| ntruhps821_decaps                |     0.2552 | ±7.016e-05 |   260 |
| ntruhrss701_keygen               |      1.432 | ±0.0008151 |    50 |
| ntruhrss701_encaps               |     0.0462 | ±4.588e-05 |   200 |
| ntruhrss701_decaps               |     0.1037 | ±9.147e-05 |    80 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.5246 | ±0.0004164 |    50 |
| ntruees401ep1_encrypt            |    0.07951 | ±0.002991 |    50 |
| ntruees401ep1_decrypt            |     0.1275 | ±0.0001506 |    80 |
| ntruees443ep1_keygen             |     0.5126 | ±0.0003972 |    54 |
| ntruees443ep1_encrypt            |    0.02425 | ±0.0001174 |    50 |
| ntruees443ep1_decrypt            |     0.0354 | ±8.65e-05 |    80 |
| ntruees449ep1_keygen             |     0.6229 | ±0.0005313 |   530 |
| ntruees449ep1_encrypt            |     0.1152 | ±0.007062 |    50 |
| ntruees449ep1_decrypt            |     0.1644 | ±0.0001591 |   350 |
| ntruees541ep1_keygen             |      0.438 | ±0.0004614 |    88 |
| ntruees541ep1_encrypt            |    0.04595 | ±5.644e-05 |   114 |
| ntruees541ep1_decrypt            |     0.0765 | ±0.0001244 |   110 |
| ntruees677ep1_keygen             |     0.7067 | ±0.0004068 |   111 |
| ntruees677ep1_encrypt            |     0.1475 | ±0.0001222 |    85 |
| ntruees677ep1_decrypt            |     0.2684 | ±0.0002338 |    56 |
| ntruees1087ep1_keygen            |     0.9854 |  ±0.00113 |    80 |
| ntruees1087ep1_encrypt           |    0.09963 | ±8.105e-05 |    80 |
| ntruees1087ep1_decrypt           |     0.1936 | ±0.0005642 |    50 |
| ntruees1087ep2_keygen            |      1.043 | ±0.002625 |    50 |
| ntruees1087ep2_encrypt           |     0.1755 | ±0.0001843 |    50 |
| ntruees1087ep2_decrypt           |     0.3552 | ±0.0007278 |   110 |
| ntruees1171ep1_keygen            |      1.114 | ±0.001566 |   140 |
| ntruees1171ep1_encrypt           |     0.1685 | ±0.0002223 |    50 |
| ntruees1171ep1_decrypt           |     0.3112 | ±0.0004232 |    50 |
| ntruees1499ep1_keygen            |      1.771 | ±0.001282 |   110 |
| ntruees1499ep1_encrypt           |     0.1629 | ±0.0002058 |    50 |
| ntruees1499ep1_decrypt           |     0.3071 | ±0.0003582 |    86 |

