
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      46.71 |   ±0.1011 |   113 |
| rsa_encrypt_1024                 |    0.01562 | ±8.584e-05 |    50 |
| rsa_decrypt_1024                 |     0.2663 | ±0.001074 |   170 |
| rsa_sign_1024                    |     0.2677 |  ±0.00127 |    81 |
| rsa_verify_1024                  |    0.01608 | ±7.856e-05 |    50 |
| elgamal_keygen_1024              |      80.54 |    ±0.157 |   110 |
| elgamal_encrypt_1024             |     0.4151 | ±0.003516 |    50 |
| elgamal_decrypt_1024             |     0.1998 | ±0.0009846 |    80 |
| dsa_keygen_1024                  |      58.02 |  ±0.07967 |   177 |
| dsa_sign_1024                    |     0.2449 | ±0.0007453 |   110 |
| dsa_verify_1024                  |     0.4383 | ±0.001041 |    56 |
| paillier_keygen_1024             |       31.7 |  ±0.04297 |    59 |
| paillier_encrypt_1024            |      3.787 |   ±0.0108 |    50 |
| paillier_decrypt_1024            |      2.823 |  ±0.01299 |    82 |
| paillier_rerandomize_1024        |      2.941 | ±0.005214 |    50 |
| paillier_add_1024                |    0.01502 | ±4.216e-05 |    50 |
| cocks_keygen_1024                |      28.73 |  ±0.02814 |    85 |
| cocks_encrypt_1024               |     0.9546 | ±0.001463 |   112 |
| cocks_decrypt_1024               |     0.1242 | ±0.0002001 |    80 |
| rabin_keygen_1024                |      33.97 |  ±0.05819 |    52 |
| rabin_encrypt_1024               |   0.004378 | ±1.581e-05 |    80 |
| rabin_decrypt_1024               |     0.2612 | ±0.000761 |    80 |
| schmidt_samoa_keygen_1024        |      12.52 |   ±0.0172 |    50 |
| schmidt_samoa_encrypt_1024       |     0.9898 | ±0.001367 |    53 |
| schmidt_samoa_decrypt_1024       |     0.2736 | ±0.0005841 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      472.6 |   ±0.4037 |    50 |
| rsa_encrypt_2048                 |    0.04928 | ±0.0001883 |    50 |
| rsa_decrypt_2048                 |      1.648 | ±0.004805 |    50 |
| rsa_sign_2048                    |      1.672 | ±0.006769 |    80 |
| rsa_verify_2048                  |    0.04927 | ±0.0002926 |    51 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.9112 | ±0.0007293 |    80 |
| ecdsa_sign                       |     0.9439 | ±0.000494 |    50 |
| ecdsa_verify                     |      1.838 | ±0.001949 |    80 |
| ecdh_keygen                      |     0.9113 | ±0.0007938 |    50 |
| ecdh_agree                       |     0.9009 | ±0.000773 |    50 |
| ecdh_serialize                   |  0.0001103 | ±2.205e-06 |   100 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      0.912 | ±0.0009402 |   110 |
| ecies_encrypt                    |      1.814 |  ±0.00204 |    50 |
| ecies_decrypt                    |     0.9016 | ±0.001106 |   110 |
| ec_elgamal_keygen                |     0.9114 | ±0.0007747 |    50 |
| ec_elgamal_encrypt               |      1.911 | ±0.001484 |   110 |
| ec_elgamal_decrypt               |     0.9304 | ±0.001067 |   170 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      1.091 | ±0.0009148 |   140 |
| ed25519_sign                     |     0.5233 | ±0.0005169 |    86 |
| ed25519_verify                   |      1.756 | ±0.001222 |   110 |
| edwards_dh_keygen                |      1.055 | ±0.0008103 |    50 |
| edwards_dh_agree                 |     0.5215 | ±0.0004529 |    80 |
| edwards_dh_serialize             |  6.002e-05 | ±2.406e-06 |   185 |
| edwards_elgamal_keygen           |      1.055 | ±0.0009573 |    50 |
| edwards_elgamal_encrypt          |      1.111 | ±0.001037 |    50 |
| edwards_elgamal_decrypt          |     0.8869 | ±0.0009629 |    52 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.06613 | ±0.0001387 |    80 |
| x25519_agree                     |    0.06484 | ±0.0001384 |    50 |
| x25519_scalar_mult_base          |    0.06486 | ±0.0001734 |    50 |
| x25519_scalar_mult               |    0.06486 | ±0.0001528 |    80 |
| x448_keygen                      |     0.3645 | ±0.0005598 |    80 |
| x448_agree                       |      0.363 | ±0.0005443 |    50 |
| x448_scalar_mult_base            |     0.3635 | ±0.0006108 |    50 |
| x448_scalar_mult                 |     0.3631 | ±0.0006711 |    53 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.02626 | ±0.0002278 |    54 |
| mlkem512_encaps                  |     0.0196 | ±0.0002527 |    57 |
| mlkem512_decaps                  |    0.02242 | ±0.0001954 |   112 |
| mlkem768_keygen                  |    0.04404 | ±0.0004195 |    50 |
| mlkem768_encaps                  |    0.02688 | ±0.0003154 |    50 |
| mlkem768_decaps                  |    0.03127 | ±0.0002772 |    80 |
| mlkem1024_keygen                 |    0.06712 | ±0.0007828 |    50 |
| mlkem1024_encaps                 |    0.03732 | ±0.0004799 |    82 |
| mlkem1024_decaps                 |    0.04288 | ±0.0003611 |    50 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.0954 | ±0.0005087 |    52 |
| mldsa44_sign                     |     0.3109 | ±0.001191 |    80 |
| mldsa44_verify                   |    0.03446 | ±0.0003605 |    50 |
| mldsa65_keygen                   |     0.1706 | ±0.0009733 |    50 |
| mldsa65_sign                     |     0.5395 | ±0.001742 |    50 |
| mldsa65_verify                   |    0.04874 | ±0.0005093 |   110 |
| mldsa87_keygen                   |     0.2482 | ±0.001166 |   170 |
| mldsa87_sign                     |     0.3418 | ±0.001506 |    50 |
| mldsa87_verify                   |    0.07422 | ±0.0007261 |    50 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.308 | ±0.004394 |    80 |
| ntruhps509_encaps                |     0.1094 | ±0.0006578 |    80 |
| ntruhps509_decaps                |     0.1592 | ±0.000874 |    50 |
| ntruhps677_keygen                |      1.865 | ±0.004605 |    50 |
| ntruhps677_encaps                |     0.1381 | ±0.0008496 |    80 |
| ntruhps677_decaps                |     0.1686 | ±0.002402 |    82 |
| ntruhps821_keygen                |      2.883 | ±0.005111 |    50 |
| ntruhps821_encaps                |     0.2015 | ±0.001515 |    50 |
| ntruhps821_decaps                |     0.2903 | ±0.001444 |   116 |
| ntruhrss701_keygen               |       1.89 | ±0.003288 |    50 |
| ntruhrss701_encaps               |    0.06998 | ±0.0007069 |   140 |
| ntruhrss701_decaps               |     0.1738 | ±0.0008715 |    50 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.9664 |  ±0.01377 |    50 |
| ntruees401ep1_encrypt            |     0.1106 | ±0.001106 |   113 |
| ntruees401ep1_decrypt            |     0.1615 | ±0.008727 |    50 |
| ntruees443ep1_keygen             |     0.8692 | ±0.002609 |    50 |
| ntruees443ep1_encrypt            |    0.04498 | ±0.0004609 |   170 |
| ntruees443ep1_decrypt            |    0.04995 | ±0.000548 |    50 |
| ntruees449ep1_keygen             |       1.13 | ±0.004091 |    50 |
| ntruees449ep1_encrypt            |     0.1556 | ±0.001178 |   170 |
| ntruees449ep1_decrypt            |     0.1974 | ±0.001387 |    50 |
| ntruees541ep1_keygen             |      1.058 | ±0.004782 |    80 |
| ntruees541ep1_encrypt            |    0.07611 | ±0.0008384 |    51 |
| ntruees541ep1_decrypt            |     0.1028 | ±0.004942 |    80 |
| ntruees677ep1_keygen             |      1.621 | ±0.005894 |   114 |
| ntruees677ep1_encrypt            |     0.2017 | ±0.001649 |    81 |
| ntruees677ep1_decrypt            |     0.3252 | ±0.002043 |   140 |
| ntruees1087ep1_keygen            |      2.687 | ±0.006388 |    50 |
| ntruees1087ep1_encrypt           |     0.1564 | ±0.001568 |   110 |
| ntruees1087ep1_decrypt           |     0.2307 | ±0.001816 |    80 |
| ntruees1087ep2_keygen            |      2.812 | ±0.009131 |    80 |
| ntruees1087ep2_encrypt           |     0.2483 | ±0.002281 |    84 |
| ntruees1087ep2_decrypt           |     0.4009 | ±0.002749 |    50 |
| ntruees1171ep1_keygen            |      3.015 |  ±0.01813 |   110 |
| ntruees1171ep1_encrypt           |     0.2412 | ±0.002981 |   140 |
| ntruees1171ep1_decrypt           |     0.3806 | ±0.003106 |   170 |
| ntruees1499ep1_keygen            |      4.374 |  ±0.01748 |    50 |
| ntruees1499ep1_encrypt           |     0.2413 | ±0.002655 |    53 |
| ntruees1499ep1_decrypt           |     0.3775 | ±0.003951 |    50 |

