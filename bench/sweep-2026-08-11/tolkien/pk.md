
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      39.35 |   ±0.9959 |    50 |
| rsa_encrypt_1024                 |    0.01186 | ±0.0002774 |    50 |
| rsa_decrypt_1024                 |     0.2263 | ±0.0003833 |    50 |
| rsa_sign_1024                    |     0.2248 | ±0.0003607 |    50 |
| rsa_verify_1024                  |     0.0123 | ±0.0003969 |    50 |
| elgamal_keygen_1024              |      54.54 |  ±0.04681 |    50 |
| elgamal_encrypt_1024             |     0.2778 | ±0.0002598 |    50 |
| elgamal_decrypt_1024             |     0.1351 | ±9.838e-05 |    50 |
| dsa_keygen_1024                  |      39.32 |  ±0.03666 |    50 |
| dsa_sign_1024                    |     0.1717 | ±0.0001504 |    50 |
| dsa_verify_1024                  |     0.2977 | ±0.000195 |   144 |
| paillier_keygen_1024             |      25.95 |  ±0.02531 |    50 |
| paillier_encrypt_1024            |      2.586 | ±0.0008652 |    50 |
| paillier_decrypt_1024            |      1.906 | ±0.0006735 |   110 |
| paillier_rerandomize_1024        |      2.004 | ±0.0007385 |    50 |
| paillier_add_1024                |    0.01017 | ±3.376e-06 |    51 |
| cocks_keygen_1024                |      23.89 |  ±0.02534 |    80 |
| cocks_encrypt_1024               |     0.6689 |  ±0.01354 |    55 |
| cocks_decrypt_1024               |     0.1062 | ±7.949e-05 |    86 |
| rabin_keygen_1024                |      28.04 |  ±0.02633 |    50 |
| rabin_encrypt_1024               |   0.003209 | ±2.12e-05 |   110 |
| rabin_decrypt_1024               |     0.2203 | ±0.0002371 |    53 |
| schmidt_samoa_keygen_1024        |      10.16 |  ±0.01139 |    50 |
| schmidt_samoa_encrypt_1024       |     0.6543 | ±0.001639 |    50 |
| schmidt_samoa_decrypt_1024       |     0.1886 |  ±0.00225 |   110 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      322.6 |    ±2.772 |    50 |
| rsa_encrypt_2048                 |    0.03541 | ±1.736e-05 |    50 |
| rsa_decrypt_2048                 |      1.119 | ±0.001223 |    50 |
| rsa_sign_2048                    |      1.118 |  ±0.00106 |    50 |
| rsa_verify_2048                  |    0.03498 | ±3.27e-05 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.6922 | ±0.001523 |    50 |
| ecdsa_sign                       |     0.7178 | ±0.002061 |    50 |
| ecdsa_verify                     |      1.393 | ±0.002277 |    50 |
| ecdh_keygen                      |     0.6934 | ±0.001522 |    50 |
| ecdh_agree                       |     0.6853 | ±0.0006186 |    50 |
| ecdh_serialize                   |  0.0001048 | ±2.272e-06 |   117 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |     0.6931 | ±0.0007416 |    50 |
| ecies_encrypt                    |      1.377 | ±0.0008156 |   172 |
| ecies_decrypt                    |     0.6865 | ±0.0006979 |   140 |
| ec_elgamal_keygen                |      0.692 | ±0.0007007 |    53 |
| ec_elgamal_encrypt               |       1.45 | ±0.003029 |    50 |
| ec_elgamal_decrypt               |     0.7066 | ±0.0006953 |    57 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.8009 | ±0.001653 |    50 |
| ed25519_sign                     |     0.3994 | ±0.0009579 |    80 |
| ed25519_verify                   |      1.328 | ±0.003209 |    50 |
| edwards_dh_keygen                |     0.7813 | ±0.001639 |    50 |
| edwards_dh_agree                 |     0.3966 | ±0.0008523 |    86 |
| edwards_dh_serialize             |  7.418e-05 | ±1.721e-06 |   147 |
| edwards_elgamal_keygen           |     0.7819 | ±0.002504 |    50 |
| edwards_elgamal_encrypt          |     0.8429 | ±0.002014 |    50 |
| edwards_elgamal_decrypt          |     0.6706 | ±0.004337 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.03524 | ±2.244e-06 |   119 |
| x25519_agree                     |    0.03438 | ±1.076e-05 |    80 |
| x25519_scalar_mult_base          |    0.03442 | ±1.523e-05 |    50 |
| x25519_scalar_mult               |    0.03442 | ±9.549e-06 |    80 |
| x448_keygen                      |     0.2387 | ±4.219e-05 |    80 |
| x448_agree                       |     0.2377 | ±6.014e-05 |    80 |
| x448_scalar_mult_base            |     0.2378 | ±0.0001122 |    80 |
| x448_scalar_mult                 |     0.2379 | ±0.0002164 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.01414 | ±2.029e-05 |    80 |
| mlkem512_encaps                  |    0.00867 | ±7.29e-06 |    86 |
| mlkem512_decaps                  |   0.009044 | ±9.17e-06 |    50 |
| mlkem768_keygen                  |    0.02318 | ±2.805e-05 |   170 |
| mlkem768_encaps                  |    0.01126 | ±1.085e-05 |   140 |
| mlkem768_decaps                  |      0.012 | ±1.403e-05 |   260 |
| mlkem1024_keygen                 |    0.03638 | ±5.638e-05 |    82 |
| mlkem1024_encaps                 |    0.01519 | ±2.392e-05 |    50 |
| mlkem1024_decaps                 |    0.01632 | ±1.882e-05 |   171 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.05243 | ±7.969e-05 |   110 |
| mldsa44_sign                     |       0.14 | ±6.97e-05 |    50 |
| mldsa44_verify                   |    0.01552 | ±1.605e-05 |    80 |
| mldsa65_keygen                   |    0.09676 | ±0.0001117 |   118 |
| mldsa65_sign                     |     0.2387 | ±6.914e-05 |    80 |
| mldsa65_verify                   |    0.02192 | ±1.633e-05 |    82 |
| mldsa87_keygen                   |     0.1352 | ±0.0001214 |    50 |
| mldsa87_sign                     |     0.1514 | ±7.512e-05 |    80 |
| mldsa87_verify                   |    0.03367 | ±2.656e-05 |    53 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |     0.9711 | ±0.001772 |    81 |
| ntruhps509_encaps                |     0.0818 | ±0.0001429 |    81 |
| ntruhps509_decaps                |     0.1382 | ±0.0003768 |    50 |
| ntruhps677_keygen                |      1.128 |  ±0.04444 |    50 |
| ntruhps677_encaps                |    0.08611 | ±0.002355 |    50 |
| ntruhps677_decaps                |    0.09966 | ±0.003664 |    50 |
| ntruhps821_keygen                |       2.42 | ±0.004594 |    59 |
| ntruhps821_encaps                |     0.1623 | ±0.0004615 |    50 |
| ntruhps821_decaps                |      0.292 | ±0.000697 |    50 |
| ntruhrss701_keygen               |      1.167 |  ±0.03213 |    50 |
| ntruhrss701_encaps               |    0.04679 | ±0.002884 |    50 |
| ntruhrss701_decaps               |     0.1152 | ±0.007519 |    80 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.7537 | ±0.000746 |    80 |
| ntruees401ep1_encrypt            |    0.09678 | ±8.825e-05 |    86 |
| ntruees401ep1_decrypt            |     0.1333 | ±0.0001171 |    50 |
| ntruees443ep1_keygen             |     0.7005 | ±0.0008643 |    50 |
| ntruees443ep1_encrypt            |    0.04115 | ±3.726e-05 |    87 |
| ntruees443ep1_decrypt            |    0.04026 | ±5.079e-05 |    50 |
| ntruees449ep1_keygen             |     0.8905 | ±0.001233 |   171 |
| ntruees449ep1_encrypt            |     0.1358 | ±0.0001282 |   230 |
| ntruees449ep1_decrypt            |     0.1658 | ±0.0002389 |    50 |
| ntruees541ep1_keygen             |     0.6922 | ±0.001709 |    50 |
| ntruees541ep1_encrypt            |     0.0697 | ±6.839e-05 |    50 |
| ntruees541ep1_decrypt            |     0.0839 | ±5.857e-05 |   140 |
| ntruees677ep1_keygen             |      1.126 |  ±0.02177 |    50 |
| ntruees677ep1_encrypt            |      0.174 | ±0.0002022 |    50 |
| ntruees677ep1_decrypt            |      0.267 | ±9.053e-05 |    50 |
| ntruees1087ep1_keygen            |      1.788 |  ±0.02263 |    50 |
| ntruees1087ep1_encrypt           |      0.138 | ±0.0002103 |    50 |
| ntruees1087ep1_decrypt           |     0.1845 | ±0.0001204 |    50 |
| ntruees1087ep2_keygen            |      1.888 |  ±0.02881 |    83 |
| ntruees1087ep2_encrypt           |     0.2139 | ±0.0002769 |    50 |
| ntruees1087ep2_decrypt           |     0.3237 | ±0.0001201 |   174 |
| ntruees1171ep1_keygen            |       2.07 |  ±0.04132 |    80 |
| ntruees1171ep1_encrypt           |     0.2066 |  ±0.00017 |    80 |
| ntruees1171ep1_decrypt           |     0.3095 | ±0.0001289 |    54 |
| ntruees1499ep1_keygen            |       3.17 |  ±0.06417 |    50 |
| ntruees1499ep1_encrypt           |     0.2129 | ±0.0001693 |   111 |
| ntruees1499ep1_decrypt           |     0.3038 | ±0.0007624 |   530 |

