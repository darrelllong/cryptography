
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      21.76 |      1.733 |    68 |
| rsa_encrypt_1024                 |   0.008983 |  2.387e-05 |    50 |
| rsa_decrypt_1024                 |     0.1289 |  0.0003893 |    65 |
| rsa_sign_1024                    |     0.1291 |  0.0002319 |    52 |
| rsa_verify_1024                  |   0.008917 |  2.029e-05 |    62 |
| elgamal_keygen_1024              |      33.43 |      2.802 |   590 |
| elgamal_encrypt_1024             |     0.1449 |  0.0003175 |    50 |
| elgamal_decrypt_1024             |      0.141 |   0.000489 |    50 |
| dsa_keygen_1024                  |      32.61 |      2.692 |   400 |
| dsa_sign_1024                    |    0.07693 |  0.0005065 |   100 |
| dsa_verify_1024                  |     0.1421 |  0.0003764 |   120 |
| paillier_keygen_1024             |      18.15 |     0.8596 |    50 |
| paillier_encrypt_1024            |      2.171 |   0.003832 |    50 |
| paillier_decrypt_1024            |      1.694 |   0.003289 |    76 |
| paillier_rerandomize_1024        |      1.725 |   0.003019 |    63 |
| paillier_add_1024                |   0.005879 |  9.875e-06 |    50 |
| cocks_keygen_1024                |      16.49 |     0.7464 |    50 |
| cocks_encrypt_1024               |     0.4277 |  0.0008966 |    50 |
| cocks_decrypt_1024               |     0.0575 |  0.0002341 |    50 |
| rabin_keygen_1024                |      23.15 |      1.311 |   100 |
| rabin_encrypt_1024               |   0.002471 |    2.6e-05 |    51 |
| rabin_decrypt_1024               |     0.1245 |  0.0003038 |    50 |
| schmidt_samoa_keygen_1024        |      6.857 |     0.2463 |    50 |
| schmidt_samoa_encrypt_1024       |     0.4268 |   0.001032 |    50 |
| schmidt_samoa_decrypt_1024       |     0.1343 |   0.000375 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      173.3 |      14.48 |   318 |
| rsa_encrypt_2048                 |    0.03079 |  2.856e-05 |    50 |
| rsa_decrypt_2048                 |      0.901 |   0.001429 |    50 |
| rsa_sign_2048                    |     0.9003 |   0.001063 |    82 |
| rsa_verify_2048                  |    0.03033 |  3.289e-05 |    79 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.4688 |  0.0006527 |    76 |
| ecdsa_sign                       |     0.4637 |   0.002597 |    55 |
| ecdsa_verify                     |      0.933 |   0.003138 |    50 |
| ecdh_keygen                      |     0.4694 |   0.001232 |    50 |
| ecdh_agree                       |     0.4669 |    0.03503 |    50 |
| ecdh_serialize                   |  7.694e-05 |  5.538e-07 |    50 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |     0.4689 |  0.0006619 |    50 |
| ecies_encrypt                    |     0.9666 |    0.07036 |    50 |
| ecies_decrypt                    |     0.4587 |   0.001726 |    62 |
| ec_elgamal_keygen                |     0.4697 |   0.001854 |    56 |
| ec_elgamal_encrypt               |      1.427 |    0.06008 |    50 |
| ec_elgamal_decrypt               |      1.359 |   0.002786 |    58 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.0233 |  2.863e-05 |    67 |
| ed25519_sign                     |    0.01888 |  0.0001885 |    50 |
| ed25519_verify                   |     0.6178 |   0.003172 |    50 |
| edwards_dh_keygen                |     0.5259 |    0.02128 |    50 |
| edwards_dh_agree                 |     0.2619 |  0.0007506 |    67 |
| edwards_dh_serialize             |  2.323e-05 |  1.814e-07 |    61 |
| edwards_elgamal_keygen           |     0.5195 |  0.0007574 |    51 |
| edwards_elgamal_encrypt          |     0.5763 |    0.04539 |    50 |
| edwards_elgamal_decrypt          |     0.4418 |    0.02987 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |     0.0378 |  4.822e-05 |    50 |
| x25519_agree                     |    0.03737 |   4.86e-05 |    50 |
| x25519_scalar_mult_base          |    0.03736 |  4.309e-05 |    50 |
| x25519_scalar_mult               |    0.03737 |  4.504e-05 |    50 |
| x448_keygen                      |     0.1875 |  0.0001449 |    50 |
| x448_agree                       |      0.187 |  9.698e-05 |    50 |
| x448_scalar_mult_base            |      0.187 |  0.0001399 |    50 |
| x448_scalar_mult                 |      0.187 |  7.887e-05 |    97 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.06786 |  0.0001039 |   114 |
| mlkem512_encaps                  |    0.01423 |  9.526e-05 |   153 |
| mlkem512_decaps                  |    0.01802 |  9.198e-05 |   112 |
| mlkem768_keygen                  |     0.1105 |  0.0001421 |   300 |
| mlkem768_encaps                  |    0.01878 |  0.0003286 |    50 |
| mlkem768_decaps                  |    0.02401 |  0.0001108 |   200 |
| mlkem1024_keygen                 |     0.1698 |  0.0004589 |    50 |
| mlkem1024_encaps                 |    0.02443 |  0.0002848 |    50 |
| mlkem1024_decaps                 |    0.03145 |  0.0002304 |   104 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.04427 |   0.000571 |    50 |
| mldsa44_sign                     |     0.1597 |   0.005201 |    59 |
| mldsa44_verify                   |    0.01771 |  0.0002895 |    55 |
| mldsa65_keygen                   |     0.0816 |  0.0007189 |    50 |
| mldsa65_sign                     |     0.2481 |    0.01077 |    50 |
| mldsa65_verify                   |    0.02487 |  0.0001621 |   200 |
| mldsa87_keygen                   |     0.1184 |  0.0004809 |   188 |
| mldsa87_sign                     |     0.2628 |     0.0129 |    50 |
| mldsa87_verify                   |    0.03545 |  0.0002655 |   113 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |       1.17 |   0.001243 |    99 |
| ntruhps509_encaps                |    0.04635 |  0.0001688 |   153 |
| ntruhps509_decaps                |    0.07976 |   0.000347 |    50 |
| ntruhps677_keygen                |      1.047 |  0.0008753 |    50 |
| ntruhps677_encaps                |    0.05942 |  0.0002014 |   102 |
| ntruhps677_decaps                |    0.07825 |  0.0003062 |   101 |
| ntruhps821_keygen                |      1.837 |   0.001581 |    50 |
| ntruhps821_encaps                |     0.0802 |  0.0007672 |    50 |
| ntruhps821_decaps                |     0.1302 |  0.0002514 |   550 |
| ntruhrss701_keygen               |      1.266 |  0.0009615 |    56 |
| ntruhrss701_encaps               |     0.0406 |  0.0002594 |   100 |
| ntruhrss701_decaps               |    0.09065 |  0.0005155 |    50 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | CI width (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |      0.346 |  0.0009441 |   135 |
| ntruees401ep1_encrypt            |    0.05405 |   0.002078 |    50 |
| ntruees401ep1_decrypt            |    0.09399 |   0.001045 |    50 |
| ntruees443ep1_keygen             |     0.3344 |  0.0004089 |   200 |
| ntruees443ep1_encrypt            |    0.01696 |  0.0003055 |    50 |
| ntruees443ep1_decrypt            |    0.02552 |  0.0002071 |   206 |
| ntruees449ep1_keygen             |     0.4243 |   0.001088 |   100 |
| ntruees449ep1_encrypt            |    0.08182 |   0.004662 |    61 |
| ntruees449ep1_decrypt            |     0.1206 |  0.0003739 |   174 |
| ntruees541ep1_keygen             |     0.3837 |   0.002833 |    50 |
| ntruees541ep1_encrypt            |    0.03368 |   0.002135 |    50 |
| ntruees541ep1_decrypt            |    0.05524 |   0.001616 |    50 |
| ntruees677ep1_keygen             |     0.5839 |   0.009665 |    50 |
| ntruees677ep1_encrypt            |     0.1102 |   0.002587 |    50 |
| ntruees677ep1_decrypt            |     0.2004 |    0.00125 |    50 |
| ntruees1087ep1_keygen            |      0.896 |   0.001722 |    66 |
| ntruees1087ep1_encrypt           |    0.07344 |  0.0003585 |    74 |
| ntruees1087ep1_decrypt           |     0.1328 |  0.0004771 |   110 |
| ntruees1087ep2_keygen            |     0.9426 |   0.002917 |    50 |
| ntruees1087ep2_encrypt           |     0.1315 |   0.001394 |    50 |
| ntruees1087ep2_decrypt           |     0.2431 |   0.001265 |    57 |
| ntruees1171ep1_keygen            |      1.002 |   0.004369 |    50 |
| ntruees1171ep1_encrypt           |     0.1253 |   0.001764 |    50 |
| ntruees1171ep1_decrypt           |     0.2256 |  0.0009203 |   110 |
| ntruees1499ep1_keygen            |       1.53 |   0.002403 |   144 |
| ntruees1499ep1_encrypt           |     0.1209 |  0.0008745 |    63 |
| ntruees1499ep1_decrypt           |     0.2315 |  0.0008874 |   120 |

