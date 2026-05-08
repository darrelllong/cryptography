
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      17.79 |   ±0.9056 |    50 |
| rsa_encrypt_1024                 |    0.04317 | ±0.0002373 |   110 |
| rsa_decrypt_1024                 |      0.326 | ±0.001685 |   201 |
| rsa_sign_1024                    |     0.3262 | ±0.001666 |   110 |
| rsa_verify_1024                  |    0.04322 | ±0.0001499 |    80 |
| elgamal_keygen_1024              |      82.42 |   ±0.3261 |   117 |
| elgamal_encrypt_1024             |     0.4056 | ±0.002128 |    50 |
| elgamal_decrypt_1024             |     0.2105 | ±0.003503 |    80 |
| dsa_keygen_1024                  |      59.38 |   ±0.1845 |    80 |
| dsa_sign_1024                    |     0.3591 | ±0.006232 |    50 |
| dsa_verify_1024                  |     0.5266 | ±0.001681 |   117 |
| paillier_keygen_1024             |      18.78 |  ±0.03684 |   116 |
| paillier_encrypt_1024            |      7.658 | ±0.005387 |   202 |
| paillier_decrypt_1024            |      2.853 | ±0.001856 |   170 |
| paillier_rerandomize_1024        |      4.954 |  ±0.01245 |   230 |
| paillier_add_1024                |    0.01326 | ±1.932e-05 |   140 |
| cocks_keygen_1024                |      14.65 |   ±0.2535 |    50 |
| cocks_encrypt_1024               |      0.932 | ±0.002291 |    80 |
| cocks_decrypt_1024               |      0.169 | ±0.001759 |    50 |
| rabin_keygen_1024                |      21.09 |   ±0.1053 |    80 |
| rabin_encrypt_1024               |    0.03663 | ±0.0001557 |   170 |
| rabin_decrypt_1024               |     0.3147 | ±0.001467 |   110 |
| schmidt_samoa_keygen_1024        |      7.594 |   ±0.1311 |    81 |
| schmidt_samoa_encrypt_1024       |     0.9146 | ±0.001267 |   234 |
| schmidt_samoa_decrypt_1024       |     0.2582 |  ±0.01078 |    51 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |        287 |    ±3.338 |   110 |
| rsa_encrypt_2048                 |     0.1306 | ±0.0005355 |   110 |
| rsa_decrypt_2048                 |      1.784 |  ±0.01143 |    50 |
| rsa_sign_2048                    |      1.798 |  ±0.05595 |    50 |
| rsa_verify_2048                  |     0.1311 | ±0.0007617 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |       1.99 | ±0.006535 |    50 |
| ecdsa_sign                       |      2.166 | ±0.005612 |    52 |
| ecdsa_verify                     |      4.027 |  ±0.01481 |    50 |
| ecdh_keygen                      |      1.988 | ±0.006667 |    50 |
| ecdh_agree                       |      2.059 |  ±0.03056 |    50 |
| ecdh_serialize                   |  0.0001034 | ±2.911e-06 |    50 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.992 | ±0.004656 |   110 |
| ecies_encrypt                    |      3.939 |   ±0.0117 |    50 |
| ecies_decrypt                    |      1.954 | ±0.003838 |    80 |
| ec_elgamal_keygen                |      1.985 | ±0.004116 |    55 |
| ec_elgamal_encrypt               |      4.067 |  ±0.02335 |    55 |
| ec_elgamal_decrypt               |      1.993 | ±0.005386 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |       2.03 | ±0.007771 |    50 |
| ed25519_sign                     |      1.102 | ±0.005711 |   110 |
| ed25519_verify                   |       3.33 | ±0.008169 |    50 |
| edwards_dh_keygen                |      2.035 |  ±0.04036 |    84 |
| edwards_dh_agree                 |      1.002 | ±0.002051 |    80 |
| edwards_dh_serialize             |  7.426e-05 | ±2.856e-06 |   140 |
| edwards_elgamal_keygen           |      2.015 | ±0.009597 |   110 |
| edwards_elgamal_encrypt          |      2.108 |  ±0.01187 |    50 |
| edwards_elgamal_decrypt          |      1.591 | ±0.002425 |    80 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.03499 | ±1.501e-05 |   110 |
| x25519_agree                     |    0.03416 | ±1.434e-05 |   140 |
| x25519_scalar_mult_base          |    0.03417 | ±1.659e-05 |   110 |
| x25519_scalar_mult               |    0.03417 | ±2.761e-05 |   110 |
| x448_keygen                      |     0.2373 | ±0.0008337 |    80 |
| x448_agree                       |     0.2362 | ±0.0001385 |    80 |
| x448_scalar_mult_base            |     0.2362 | ±0.0001154 |    80 |
| x448_scalar_mult                 |     0.2362 | ±0.0001106 |   140 |

### ML-KEM (Kyber)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.01703 | ±7.847e-05 |    50 |
| mlkem512_encaps                  |    0.01612 | ±2.431e-05 |    50 |
| mlkem512_decaps                  |    0.01639 | ±1.773e-05 |    80 |
| mlkem768_keygen                  |    0.02779 | ±7.227e-05 |    50 |
| mlkem768_encaps                  |    0.02594 | ±2.154e-05 |   296 |
| mlkem768_decaps                  |    0.02654 | ±9.472e-05 |   110 |
| mlkem1024_keygen                 |     0.0439 | ±6.454e-05 |    80 |
| mlkem1024_encaps                 |    0.03975 | ±6.822e-05 |    80 |
| mlkem1024_decaps                 |    0.04065 | ±3.935e-05 |   110 |

### ML-DSA (Dilithium)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.06385 | ±0.0001583 |    50 |
| mldsa44_sign                     |     0.1572 | ±7.018e-05 |    50 |
| mldsa44_verify                   |    0.01678 | ±4.972e-05 |   111 |
| mldsa65_keygen                   |     0.1179 | ±0.0002556 |    80 |
| mldsa65_sign                     |     0.2659 | ±0.0004532 |    50 |
| mldsa65_verify                   |    0.02498 | ±0.0003743 |    50 |
| mldsa87_keygen                   |     0.1726 | ±0.0002285 |   410 |
| mldsa87_sign                     |      0.168 | ±0.0001701 |   170 |
| mldsa87_verify                   |    0.03707 | ±0.000108 |   110 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.002 |  ±0.04583 |    50 |
| ntruhps509_encaps                |    0.08268 | ±0.003083 |    50 |
| ntruhps509_decaps                |     0.1455 |   ±0.0106 |    50 |
| ntruhps677_keygen                |      1.219 |  ±0.01126 |   320 |
| ntruhps677_encaps                |    0.08707 | ±0.0007503 |    50 |
| ntruhps677_decaps                |     0.1052 | ±0.002519 |    80 |
| ntruhps821_keygen                |      2.366 |  ±0.07834 |    50 |
| ntruhps821_encaps                |     0.1762 | ±0.009012 |    80 |
| ntruhps821_decaps                |     0.3096 |  ±0.01153 |    52 |
| ntruhrss701_keygen               |       1.28 |  ±0.09556 |    50 |
| ntruhrss701_encaps               |    0.04845 | ±0.001142 |    50 |
| ntruhrss701_decaps               |     0.1234 | ±0.002806 |    54 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.7645 | ±0.005618 |   140 |
| ntruees401ep1_encrypt            |     0.1008 | ±0.001312 |   171 |
| ntruees401ep1_decrypt            |     0.1385 | ±0.0003355 |   177 |
| ntruees443ep1_keygen             |     0.7524 |  ±0.02073 |    80 |
| ntruees443ep1_encrypt            |    0.04354 | ±0.0005677 |   110 |
| ntruees443ep1_decrypt            |    0.04295 | ±0.0004111 |    57 |
| ntruees449ep1_keygen             |     0.9509 |  ±0.01351 |    50 |
| ntruees449ep1_encrypt            |     0.1449 | ±0.0002934 |   140 |
| ntruees449ep1_decrypt            |     0.1771 | ±0.002304 |    50 |
| ntruees541ep1_keygen             |     0.7433 | ±0.002493 |    53 |
| ntruees541ep1_encrypt            |    0.07745 | ±0.000181 |    50 |
| ntruees541ep1_decrypt            |    0.09241 | ±0.001237 |    52 |
| ntruees677ep1_keygen             |      1.203 |  ±0.01825 |    50 |
| ntruees677ep1_encrypt            |     0.1819 | ±0.002014 |   140 |
| ntruees677ep1_decrypt            |     0.2825 | ±0.002102 |    80 |
| ntruees1087ep1_keygen            |       1.76 | ±0.005377 |   176 |
| ntruees1087ep1_encrypt           |      0.141 | ±0.0002315 |   260 |
| ntruees1087ep1_decrypt           |     0.1835 | ±0.0003071 |   230 |
| ntruees1087ep2_keygen            |      1.869 | ±0.007425 |   110 |
| ntruees1087ep2_encrypt           |     0.2148 | ±0.0006427 |    50 |
| ntruees1087ep2_decrypt           |     0.3325 | ±0.001221 |   209 |
| ntruees1499ep1_keygen            |      3.114 |  ±0.01771 |   170 |
| ntruees1499ep1_encrypt           |      0.211 | ±0.000396 |   233 |
| ntruees1499ep1_decrypt           |     0.3017 | ±0.0002866 |    50 |

