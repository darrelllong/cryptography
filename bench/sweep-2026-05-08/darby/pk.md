
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      41.03 |  ±0.01044 |    80 |
| rsa_encrypt_1024                 |    0.09092 | ±0.001591 |    50 |
| rsa_decrypt_1024                 |     0.7981 | ±0.001612 |    50 |
| rsa_sign_1024                    |     0.8024 |  ±0.01427 |    50 |
| rsa_verify_1024                  |    0.09102 | ±0.0001209 |    50 |
| elgamal_keygen_1024              |        244 |   ±0.7526 |    50 |
| elgamal_encrypt_1024             |      1.266 | ±0.001071 |    50 |
| elgamal_decrypt_1024             |     0.6525 | ±0.0004211 |    80 |
| dsa_keygen_1024                  |      176.2 |   ±0.4703 |    50 |
| dsa_sign_1024                    |     0.9262 |  ±0.01647 |    50 |
| dsa_verify_1024                  |       1.49 |  ±0.00501 |    50 |
| paillier_keygen_1024             |      46.57 |   ±0.2831 |    50 |
| paillier_encrypt_1024            |      19.47 |  ±0.00288 |    50 |
| paillier_decrypt_1024            |       9.44 | ±0.005553 |    50 |
| paillier_rerandomize_1024        |      13.47 |  ±0.05421 |    50 |
| paillier_add_1024                |    0.04363 | ±1.038e-05 |    84 |
| cocks_keygen_1024                |      34.66 |  ±0.06805 |    50 |
| cocks_encrypt_1024               |      2.795 |  ±0.01873 |    50 |
| cocks_decrypt_1024               |      0.403 | ±0.0002062 |    56 |
| rabin_keygen_1024                |      50.07 |   ±0.6358 |    50 |
| rabin_encrypt_1024               |    0.07455 | ±5.053e-05 |    54 |
| rabin_decrypt_1024               |     0.7914 |  ±0.01408 |    50 |
| schmidt_samoa_keygen_1024        |      14.73 |   ±0.1504 |   115 |
| schmidt_samoa_encrypt_1024       |      2.763 | ±0.002222 |   110 |
| schmidt_samoa_decrypt_1024       |     0.8067 | ±0.004842 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      850.5 |     ±2.95 |    52 |
| rsa_encrypt_2048                 |     0.3113 | ±0.0001877 |    80 |
| rsa_decrypt_2048                 |      5.307 | ±0.002826 |    52 |
| rsa_sign_2048                    |      5.308 |  ±0.01734 |    50 |
| rsa_verify_2048                  |     0.3128 | ±0.005454 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      3.611 |  ±0.03197 |    50 |
| ecdsa_sign                       |      3.937 |  ±0.01097 |    50 |
| ecdsa_verify                     |       7.31 |  ±0.02331 |    50 |
| ecdh_keygen                      |      3.614 |  ±0.03119 |    50 |
| ecdh_agree                       |      3.727 |  ±0.03323 |    50 |
| ecdh_serialize                   |  0.0001118 | ±3.597e-06 |    58 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      3.611 |  ±0.03745 |    50 |
| ecies_encrypt                    |      7.184 |  ±0.09285 |    50 |
| ecies_decrypt                    |      3.569 |   ±0.0409 |    50 |
| ec_elgamal_keygen                |      3.611 |  ±0.01945 |    50 |
| ec_elgamal_encrypt               |      7.394 |  ±0.02841 |    50 |
| ec_elgamal_decrypt               |      3.633 |  ±0.02232 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      3.806 |  ±0.00763 |    54 |
| ed25519_sign                     |      1.914 |  ±0.01796 |    50 |
| ed25519_verify                   |      6.246 | ±0.009423 |    50 |
| edwards_dh_keygen                |      3.763 | ±0.006105 |    50 |
| edwards_dh_agree                 |      1.878 | ±0.001706 |    52 |
| edwards_dh_serialize             |  7.718e-05 | ±1.852e-06 |    50 |
| edwards_elgamal_keygen           |      3.791 |  ±0.04686 |    50 |
| edwards_elgamal_encrypt          |       3.94 |   ±0.0231 |    50 |
| edwards_elgamal_decrypt          |      3.011 |  ±0.01664 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |     0.2165 | ±0.002467 |   118 |
| x25519_agree                     |     0.2152 | ±0.002508 |   110 |
| x25519_scalar_mult_base          |     0.2152 | ±0.002812 |    50 |
| x25519_scalar_mult               |     0.2143 | ±7.422e-05 |   115 |
| x448_keygen                      |      1.086 |  ±0.01023 |    50 |
| x448_agree                       |      1.084 |  ±0.01125 |    50 |
| x448_scalar_mult_base            |      1.087 |  ±0.01268 |    88 |
| x448_scalar_mult                 |      1.084 |  ±0.01125 |    50 |

### ML-KEM (Kyber)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.05291 | ±0.0002066 |    50 |
| mlkem512_encaps                  |    0.05284 | ±0.0001552 |   116 |
| mlkem512_decaps                  |    0.05606 | ±0.0001612 |   142 |
| mlkem768_keygen                  |    0.08631 | ±0.0003145 |    50 |
| mlkem768_encaps                  |    0.08728 | ±0.0003385 |    80 |
| mlkem768_decaps                  |     0.0914 | ±0.0002707 |    50 |
| mlkem1024_keygen                 |      0.137 | ±0.0004361 |    50 |
| mlkem1024_encaps                 |     0.1364 | ±0.0004771 |    50 |
| mlkem1024_decaps                 |     0.1428 | ±0.0003117 |   110 |

### ML-DSA (Dilithium)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.2791 | ±0.0003247 |   320 |
| mldsa44_sign                     |     0.5605 | ±0.0003453 |    80 |
| mldsa44_verify                   |    0.06158 | ±0.0008716 |    50 |
| mldsa65_keygen                   |     0.3735 | ±0.0008862 |    50 |
| mldsa65_sign                     |     0.9478 | ±0.003496 |    50 |
| mldsa65_verify                   |    0.08762 | ±0.000738 |   140 |
| mldsa87_keygen                   |      0.596 | ±0.0009311 |    52 |
| mldsa87_sign                     |     0.5985 | ±0.0009905 |   170 |
| mldsa87_verify                   |     0.1371 | ±0.000586 |   110 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      2.296 | ±0.002031 |    50 |
| ntruhps509_encaps                |     0.1729 | ±0.0003729 |    80 |
| ntruhps509_decaps                |     0.2853 | ±0.001599 |    50 |
| ntruhps677_keygen                |      3.042 | ±0.004702 |    87 |
| ntruhps677_encaps                |     0.2079 | ±0.0009669 |    50 |
| ntruhps677_decaps                |     0.2803 | ±0.0004506 |    80 |
| ntruhps821_keygen                |      5.117 | ±0.008321 |    80 |
| ntruhps821_encaps                |     0.3065 | ±0.0007033 |    50 |
| ntruhps821_decaps                |     0.4914 | ±0.001814 |   140 |
| ntruhrss701_keygen               |       3.57 | ±0.007388 |    50 |
| ntruhrss701_encaps               |     0.1175 | ±0.0003305 |    50 |
| ntruhrss701_decaps               |     0.3118 | ±0.0004736 |    85 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |      1.343 |  ±0.02541 |    53 |
| ntruees401ep1_encrypt            |     0.2898 | ±0.0009549 |    80 |
| ntruees401ep1_decrypt            |     0.4851 | ±0.002529 |   170 |
| ntruees443ep1_keygen             |      1.308 | ±0.002847 |   110 |
| ntruees443ep1_encrypt            |    0.07591 | ±0.0006669 |   260 |
| ntruees443ep1_decrypt            |      0.105 | ±0.0005188 |    50 |
| ntruees449ep1_keygen             |      1.624 | ±0.001674 |    50 |
| ntruees449ep1_encrypt            |     0.3414 | ±0.0007413 |    50 |
| ntruees449ep1_decrypt            |     0.4925 | ±0.0007877 |    50 |
| ntruees541ep1_keygen             |      1.375 | ±0.002495 |    50 |
| ntruees541ep1_encrypt            |     0.1992 | ±0.0009162 |   561 |
| ntruees541ep1_decrypt            |     0.2991 | ±0.0006596 |    50 |
| ntruees677ep1_keygen             |      2.373 | ±0.001855 |   140 |
| ntruees677ep1_encrypt            |      0.464 | ±0.003442 |    50 |
| ntruees677ep1_decrypt            |      0.828 | ±0.0008432 |    50 |
| ntruees1087ep1_keygen            |      3.701 | ±0.002887 |    80 |
| ntruees1087ep1_encrypt           |     0.3323 | ±0.0005843 |   110 |
| ntruees1087ep1_decrypt           |      0.564 |  ±0.00616 |    80 |
| ntruees1087ep2_keygen            |      3.843 | ±0.002942 |   140 |
| ntruees1087ep2_encrypt           |     0.5671 | ±0.001289 |   201 |
| ntruees1087ep2_decrypt           |      1.014 | ±0.001434 |    80 |
| ntruees1499ep1_keygen            |      7.366 | ±0.004614 |   147 |
| ntruees1499ep1_encrypt           |     0.5393 | ±0.001081 |    50 |
| ntruees1499ep1_decrypt           |     0.9457 | ±0.008248 |    50 |

