
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      39.18 |    ±3.064 |   110 |
| rsa_encrypt_1024                 |    0.01635 | ±8.026e-05 |    50 |
| rsa_decrypt_1024                 |     0.2606 | ±0.0009645 |    57 |
| rsa_sign_1024                    |     0.2622 | ±0.001902 |    50 |
| rsa_verify_1024                  |    0.01626 | ±9.416e-05 |    50 |
| elgamal_keygen_1024              |      60.76 |    ±29.58 |  2369 (limit) |
| elgamal_encrypt_1024             |     0.2858 | ±0.001082 |    50 |
| elgamal_decrypt_1024             |     0.2793 | ±0.001199 |    55 |
| dsa_keygen_1024                  |      61.48 |    ±12.94 |  1582 (limit) |
| dsa_sign_1024                    |     0.1507 | ±0.002223 |   110 |
| dsa_verify_1024                  |     0.2798 | ±0.002309 |    50 |
| paillier_keygen_1024             |      33.56 |    ±1.205 |    80 |
| paillier_encrypt_1024            |      3.778 |  ±0.01333 |    51 |
| paillier_decrypt_1024            |      2.963 |  ±0.01199 |    50 |
| paillier_rerandomize_1024        |          3 | ±0.009976 |    80 |
| paillier_add_1024                |   0.009448 | ±5.143e-05 |    83 |
| cocks_keygen_1024                |       30.3 |    ±1.279 |    50 |
| cocks_encrypt_1024               |      0.865 |  ±0.00287 |    50 |
| cocks_decrypt_1024               |     0.1208 | ±0.0003993 |    50 |
| rabin_keygen_1024                |      42.92 |    ±3.038 |    80 |
| rabin_encrypt_1024               |    0.00463 | ±2.865e-05 |    53 |
| rabin_decrypt_1024               |     0.2543 | ±0.0008694 |    86 |
| schmidt_samoa_keygen_1024        |      12.37 |   ±0.3681 |    50 |
| schmidt_samoa_encrypt_1024       |     0.8656 | ±0.002865 |    50 |
| schmidt_samoa_decrypt_1024       |     0.2693 | ±0.0009406 |   110 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      347.6 |    ±60.25 |   857 (limit) |
| rsa_encrypt_2048                 |    0.05019 | ±0.0002555 |    50 |
| rsa_decrypt_2048                 |      1.787 | ±0.006917 |    50 |
| rsa_sign_2048                    |      1.786 | ±0.009316 |    50 |
| rsa_verify_2048                  |    0.04959 | ±0.0003701 |    52 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      1.104 |  ±0.00191 |   175 |
| ecdsa_sign                       |      1.108 | ±0.004081 |    50 |
| ecdsa_verify                     |      2.223 | ±0.008028 |    50 |
| ecdh_keygen                      |      1.098 | ±0.003384 |    50 |
| ecdh_agree                       |      1.088 | ±0.005509 |    50 |
| ecdh_serialize                   |  0.0002344 | ±6.346e-06 |    50 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.098 | ±0.003136 |    50 |
| ecies_encrypt                    |      2.191 | ±0.004529 |    50 |
| ecies_decrypt                    |      1.099 | ±0.005116 |    50 |
| ec_elgamal_keygen                |      1.104 | ±0.003981 |    50 |
| ec_elgamal_encrypt               |      3.332 |  ±0.01141 |    52 |
| ec_elgamal_decrypt               |      3.222 | ±0.008345 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |    0.05146 | ±0.0001278 |    56 |
| ed25519_sign                     |    0.04233 | ±0.0002365 |    50 |
| ed25519_verify                   |      1.429 | ±0.003397 |    50 |
| edwards_dh_keygen                |      1.203 | ±0.001794 |    50 |
| edwards_dh_agree                 |     0.6098 | ±0.002479 |    58 |
| edwards_dh_serialize             |   6.79e-05 | ±2.881e-06 |   110 |
| edwards_elgamal_keygen           |       1.21 | ±0.001135 |    50 |
| edwards_elgamal_encrypt          |      1.287 | ±0.001373 |    80 |
| edwards_elgamal_decrypt          |     0.9803 | ±0.001501 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.06831 | ±0.0001838 |   201 |
| x25519_agree                     |    0.06748 | ±0.0001546 |    50 |
| x25519_scalar_mult_base          |     0.0675 | ±0.0001579 |    59 |
| x25519_scalar_mult               |    0.06752 | ±0.0001536 |    50 |
| x448_keygen                      |     0.3605 | ±0.0007501 |    50 |
| x448_agree                       |     0.3593 | ±0.0009383 |    80 |
| x448_scalar_mult_base            |     0.3594 | ±0.0008214 |    50 |
| x448_scalar_mult                 |     0.3597 | ±0.0008226 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |     0.1508 | ±0.0008338 |   170 |
| mlkem512_encaps                  |    0.03544 | ±0.0002962 |    55 |
| mlkem512_decaps                  |    0.04574 | ±0.0003122 |    50 |
| mlkem768_keygen                  |     0.2391 |  ±0.00149 |   620 |
| mlkem768_encaps                  |    0.04839 | ±0.0004886 |    50 |
| mlkem768_decaps                  |    0.06271 | ±0.0006106 |    50 |
| mlkem1024_keygen                 |     0.3602 | ±0.003643 |    50 |
| mlkem1024_encaps                 |    0.06511 | ±0.0007155 |    80 |
| mlkem1024_decaps                 |    0.08341 | ±0.0007845 |    80 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.1071 | ±0.0005769 |    80 |
| mldsa44_sign                     |     0.4339 |  ±0.01272 |    50 |
| mldsa44_verify                   |    0.04699 | ±0.0004004 |    50 |
| mldsa65_keygen                   |     0.1929 |  ±0.00109 |    50 |
| mldsa65_sign                     |     0.6872 |  ±0.03078 |    50 |
| mldsa65_verify                   |    0.06727 | ±0.0007744 |    58 |
| mldsa87_keygen                   |     0.2899 | ±0.003198 |    50 |
| mldsa87_sign                     |     0.6963 |  ±0.03306 |    87 |
| mldsa87_verify                   |    0.09643 | ±0.0008147 |    80 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.938 | ±0.007551 |    50 |
| ntruhps509_encaps                |    0.08845 | ±0.0005963 |   110 |
| ntruhps509_decaps                |     0.1328 | ±0.0008157 |    80 |
| ntruhps677_keygen                |      1.877 |  ±0.01138 |    50 |
| ntruhps677_encaps                |     0.1252 | ±0.001254 |   142 |
| ntruhps677_decaps                |     0.1401 | ±0.0008394 |   112 |
| ntruhps821_keygen                |      3.292 |  ±0.02593 |    50 |
| ntruhps821_encaps                |     0.1639 | ±0.001484 |    50 |
| ntruhps821_decaps                |     0.2359 | ±0.002482 |    50 |
| ntruhrss701_keygen               |      2.305 |  ±0.03568 |    50 |
| ntruhrss701_encaps               |    0.07613 | ±0.001293 |    50 |
| ntruhrss701_decaps               |     0.1692 | ±0.002406 |    80 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.6301 | ±0.002993 |   112 |
| ntruees401ep1_encrypt            |     0.1399 | ±0.003794 |   110 |
| ntruees401ep1_decrypt            |     0.2184 | ±0.003044 |   116 |
| ntruees443ep1_keygen             |     0.6179 | ±0.003917 |    80 |
| ntruees443ep1_encrypt            |    0.03429 | ±0.0003261 |    50 |
| ntruees443ep1_decrypt            |    0.05331 | ±0.000565 |   110 |
| ntruees449ep1_keygen             |     0.7635 | ±0.008173 |    52 |
| ntruees449ep1_encrypt            |      0.179 |  ±0.01109 |    50 |
| ntruees449ep1_decrypt            |     0.2823 | ±0.002958 |    87 |
| ntruees541ep1_keygen             |     0.6995 | ±0.003305 |    89 |
| ntruees541ep1_encrypt            |    0.07183 | ±0.0008767 |   230 |
| ntruees541ep1_decrypt            |     0.1245 | ±0.001059 |    59 |
| ntruees677ep1_keygen             |      1.045 | ±0.004152 |    86 |
| ntruees677ep1_encrypt            |     0.2453 | ±0.001862 |    80 |
| ntruees677ep1_decrypt            |     0.4989 | ±0.004675 |    50 |
| ntruees1087ep1_keygen            |      1.664 | ±0.007338 |   140 |
| ntruees1087ep1_encrypt           |     0.1633 | ±0.001675 |    50 |
| ntruees1087ep1_decrypt           |     0.3166 | ±0.002017 |   110 |
| ntruees1087ep2_keygen            |      1.755 | ±0.007532 |    50 |
| ntruees1087ep2_encrypt           |     0.2938 | ±0.002415 |    50 |
| ntruees1087ep2_decrypt           |     0.5907 | ±0.008194 |    50 |
| ntruees1171ep1_keygen            |      1.855 |  ±0.01017 |    50 |
| ntruees1171ep1_encrypt           |     0.2959 | ±0.002808 |   200 |
| ntruees1171ep1_decrypt           |     0.5391 | ±0.004929 |   111 |
| ntruees1499ep1_keygen            |      2.756 |  ±0.02302 |   110 |
| ntruees1499ep1_encrypt           |     0.2701 | ±0.002626 |    50 |
| ntruees1499ep1_decrypt           |     0.5349 | ±0.004997 |    50 |

