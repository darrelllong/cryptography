
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      22.49 |   ±0.1048 |    50 |
| rsa_encrypt_1024                 |    0.05593 | ±0.0003877 |    50 |
| rsa_decrypt_1024                 |     0.4188 | ±0.002015 |    57 |
| rsa_sign_1024                    |     0.4197 | ±0.001344 |    50 |
| rsa_verify_1024                  |    0.05616 | ±0.0001574 |   110 |
| elgamal_keygen_1024              |      118.5 |   ±0.1654 |    50 |
| elgamal_encrypt_1024             |     0.5919 | ±0.002056 |    50 |
| elgamal_decrypt_1024             |     0.3051 | ±0.001142 |    80 |
| dsa_keygen_1024                  |      85.73 |   ±0.1615 |   170 |
| dsa_sign_1024                    |     0.5384 | ±0.001327 |    80 |
| dsa_verify_1024                  |     0.7889 | ±0.006818 |    59 |
| paillier_keygen_1024             |      24.88 |      ±0.2 |    50 |
| paillier_encrypt_1024            |      11.39 |  ±0.02877 |    80 |
| paillier_decrypt_1024            |      4.118 |  ±0.05992 |    50 |
| paillier_rerandomize_1024        |      7.296 |  ±0.01047 |    50 |
| paillier_add_1024                |    0.01893 | ±6.899e-05 |    50 |
| cocks_keygen_1024                |      18.78 |  ±0.05254 |    80 |
| cocks_encrypt_1024               |      1.352 | ±0.003914 |    50 |
| cocks_decrypt_1024               |     0.2144 | ±0.001535 |    50 |
| rabin_keygen_1024                |      27.26 |  ±0.08139 |    50 |
| rabin_encrypt_1024               |    0.04874 | ±0.0001494 |    50 |
| rabin_decrypt_1024               |     0.4074 |  ±0.00123 |    52 |
| schmidt_samoa_keygen_1024        |      8.758 |   ±0.2689 |    50 |
| schmidt_samoa_encrypt_1024       |      1.335 |  ±0.00233 |    50 |
| schmidt_samoa_decrypt_1024       |     0.3853 | ±0.005221 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |        415 |    ±1.251 |   110 |
| rsa_encrypt_2048                 |      0.186 |   ±0.0004 |   145 |
| rsa_decrypt_2048                 |      2.555 | ±0.006951 |    50 |
| rsa_sign_2048                    |      2.546 | ±0.006619 |    80 |
| rsa_verify_2048                  |     0.1858 | ±0.0005796 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      2.437 | ±0.008313 |    80 |
| ecdsa_sign                       |      2.704 |  ±0.00652 |    50 |
| ecdsa_verify                     |      4.977 | ±0.007851 |    50 |
| ecdh_keygen                      |      2.438 | ±0.005295 |    50 |
| ecdh_agree                       |      2.511 | ±0.006395 |    50 |
| ecdh_serialize                   |  7.726e-05 | ±6.443e-06 |   101 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      2.446 | ±0.008863 |   140 |
| ecies_encrypt                    |      4.835 | ±0.008796 |    50 |
| ecies_decrypt                    |       2.39 | ±0.004669 |    85 |
| ec_elgamal_keygen                |      2.432 |  ±0.01028 |    50 |
| ec_elgamal_encrypt               |      4.973 |  ±0.01116 |    50 |
| ec_elgamal_decrypt               |      2.452 | ±0.008972 |   110 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      2.515 | ±0.008311 |   170 |
| ed25519_sign                     |      1.264 |  ±0.00618 |    50 |
| ed25519_verify                   |      4.126 | ±0.008502 |    52 |
| edwards_dh_keygen                |      2.477 | ±0.004674 |    50 |
| edwards_dh_agree                 |      1.237 | ±0.003963 |   142 |
| edwards_dh_serialize             |  7.204e-05 | ±4.252e-06 |    50 |
| edwards_elgamal_keygen           |      2.466 | ±0.003901 |    50 |
| edwards_elgamal_encrypt          |      2.591 |  ±0.00472 |    50 |
| edwards_elgamal_decrypt          |      1.935 | ±0.005726 |    80 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.06482 | ±0.0001863 |    50 |
| x25519_agree                     |    0.06353 | ±0.0001281 |    51 |
| x25519_scalar_mult_base          |    0.06361 | ±0.0001665 |   110 |
| x25519_scalar_mult               |    0.06367 | ±0.000157 |    59 |
| x448_keygen                      |     0.3623 | ±0.0005169 |    50 |
| x448_agree                       |     0.3629 | ±0.005327 |    50 |
| x448_scalar_mult_base            |     0.3613 | ±0.0006512 |    50 |
| x448_scalar_mult                 |     0.3612 | ±0.0006672 |    50 |

### ML-KEM (Kyber)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.02536 | ±5.482e-05 |    80 |
| mlkem512_encaps                  |    0.02665 | ±0.0006511 |    50 |
| mlkem512_decaps                  |    0.02991 | ±0.0003324 |    50 |
| mlkem768_keygen                  |    0.04218 | ±0.0003994 |   110 |
| mlkem768_encaps                  |     0.0419 | ±0.0001054 |    50 |
| mlkem768_decaps                  |    0.04684 | ±9.01e-05 |    50 |
| mlkem1024_keygen                 |    0.06593 | ±0.0007346 |    50 |
| mlkem1024_encaps                 |    0.06373 | ±0.0002676 |    50 |
| mlkem1024_decaps                 |    0.07061 | ±0.0001176 |    56 |

### ML-DSA (Dilithium)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.09451 | ±0.0001812 |   110 |
| mldsa44_sign                     |     0.3812 | ±0.001324 |    50 |
| mldsa44_verify                   |    0.03896 | ±0.000121 |    80 |
| mldsa65_keygen                   |     0.1692 | ±0.001079 |   110 |
| mldsa65_sign                     |     0.6691 | ±0.001186 |    80 |
| mldsa65_verify                   |    0.05598 | ±0.0001238 |   591 |
| mldsa87_keygen                   |     0.2448 | ±0.0007543 |    50 |
| mldsa87_sign                     |     0.4168 | ±0.001193 |    52 |
| mldsa87_verify                   |    0.08329 | ±0.0002082 |    80 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.278 | ±0.002711 |    58 |
| ntruhps509_encaps                |     0.1069 | ±0.0004561 |    50 |
| ntruhps509_decaps                |      0.156 | ±0.001382 |   110 |
| ntruhps677_keygen                |      1.798 | ±0.007316 |    53 |
| ntruhps677_encaps                |     0.1333 | ±0.001523 |    50 |
| ntruhps677_decaps                |     0.1591 | ±0.000419 |   260 |
| ntruhps821_keygen                |      2.814 |  ±0.01177 |    50 |
| ntruhps821_encaps                |     0.1937 | ±0.0004173 |    80 |
| ntruhps821_decaps                |      0.279 | ±0.0006073 |    80 |
| ntruhrss701_keygen               |      1.904 |  ±0.01062 |    54 |
| ntruhrss701_encaps               |    0.06901 | ±0.004323 |    50 |
| ntruhrss701_decaps               |     0.1691 | ±0.0004149 |   112 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.9366 | ±0.002872 |    50 |
| ntruees401ep1_encrypt            |     0.1091 | ±0.004532 |    80 |
| ntruees401ep1_decrypt            |     0.1582 |  ±0.00105 |    81 |
| ntruees443ep1_keygen             |      0.862 |  ±0.02262 |    50 |
| ntruees443ep1_encrypt            |    0.04403 | ±0.0003447 |    80 |
| ntruees443ep1_decrypt            |    0.04917 | ±0.0003307 |    50 |
| ntruees449ep1_keygen             |      1.113 |  ±0.00314 |    50 |
| ntruees449ep1_encrypt            |     0.1545 | ±0.003887 |    50 |
| ntruees449ep1_decrypt            |     0.1991 | ±0.001424 |   382 |
| ntruees541ep1_keygen             |      1.044 |  ±0.02334 |    50 |
| ntruees541ep1_encrypt            |    0.07411 | ±0.0007479 |   112 |
| ntruees541ep1_decrypt            |     0.0998 | ±0.0008372 |   140 |
| ntruees677ep1_keygen             |      1.585 | ±0.009279 |    50 |
| ntruees677ep1_encrypt            |     0.2004 | ±0.002973 |    55 |
| ntruees677ep1_decrypt            |     0.3248 | ±0.003849 |    50 |
| ntruees1087ep1_keygen            |      2.649 |  ±0.06399 |    50 |
| ntruees1087ep1_encrypt           |     0.1547 | ±0.0009354 |    50 |
| ntruees1087ep1_decrypt           |     0.2254 | ±0.0009941 |    80 |
| ntruees1087ep2_keygen            |      2.764 | ±0.007286 |    56 |
| ntruees1087ep2_encrypt           |      0.244 | ±0.0009286 |    50 |
| ntruees1087ep2_decrypt           |     0.3946 | ±0.001984 |    80 |
| ntruees1499ep1_keygen            |      4.314 |  ±0.01051 |    80 |
| ntruees1499ep1_encrypt           |     0.2415 | ±0.001777 |    80 |
| ntruees1499ep1_decrypt           |     0.3725 | ±0.002614 |    50 |

