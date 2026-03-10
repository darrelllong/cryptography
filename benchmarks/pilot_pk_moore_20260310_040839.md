
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      26.93 |  ±0.05663 |    56 |
| rsa_encrypt_1024                 |    0.05446 | ±0.001904 |    30 |
| rsa_decrypt_1024                 |     0.4401 | ±0.001666 |    30 |
| rsa_sign_1024                    |     0.4409 | ±0.001907 |    30 |
| rsa_verify_1024                  |    0.05429 | ±0.0002106 |    72 |
| elgamal_keygen_1024              |      82.86 |   ±0.2081 |    30 |
| elgamal_encrypt_1024             |     0.5962 | ±0.002634 |    61 |
| elgamal_decrypt_1024             |     0.3061 | ±0.001655 |    60 |
| dsa_keygen_1024                  |      92.45 |   ±0.2895 |    35 |
| dsa_sign_1024                    |     0.5373 | ±0.003699 |    30 |
| dsa_verify_1024                  |     0.7896 | ±0.003263 |    45 |
| paillier_keygen_1024             |      28.27 |  ±0.05507 |    30 |
| paillier_encrypt_1024            |      11.22 |  ±0.04041 |    30 |
| paillier_decrypt_1024            |      4.063 |  ±0.01267 |    30 |
| paillier_rerandomize_1024        |      7.196 |  ±0.02771 |    30 |
| paillier_add_1024                |    0.01279 | ±5.449e-05 |    47 |
| cocks_keygen_1024                |      22.17 |  ±0.06165 |    62 |
| cocks_encrypt_1024               |      1.345 | ±0.004421 |    60 |
| cocks_decrypt_1024               |     0.2238 | ±0.0008023 |    30 |
| rabin_keygen_1024                |      35.99 |   ±0.1001 |    30 |
| rabin_encrypt_1024               |    0.04765 | ±0.000257 |    31 |
| rabin_decrypt_1024               |      0.429 | ±0.001723 |   106 |
| schmidt_samoa_keygen_1024        |      9.127 |  ±0.04093 |    31 |
| schmidt_samoa_encrypt_1024       |      1.338 |  ±0.01203 |    30 |
| schmidt_samoa_decrypt_1024       |     0.3935 | ±0.000984 |    30 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      279.6 |   ±0.6563 |    30 |
| rsa_encrypt_2048                 |     0.1809 | ±0.0005757 |    35 |
| rsa_decrypt_2048                 |      2.565 |  ±0.01206 |    36 |
| rsa_sign_2048                    |      2.571 |  ±0.01237 |    71 |
| rsa_verify_2048                  |     0.1814 | ±0.000872 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      2.438 | ±0.006522 |    60 |
| ecdsa_sign                       |      2.707 |  ±0.01028 |    54 |
| ecdsa_verify                     |       5.06 |  ±0.01548 |    35 |
| ecdh_keygen                      |      2.435 |  ±0.01122 |    31 |
| ecdh_agree                       |      2.493 | ±0.006536 |    30 |
| ecdh_serialize                   |  7.927e-05 | ±3.787e-06 |    60 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      2.435 |  ±0.00741 |    36 |
| ecies_encrypt                    |      4.818 |  ±0.02041 |    30 |
| ecies_decrypt                    |      2.381 | ±0.007384 |    30 |
| ec_elgamal_keygen                |       2.43 |  ±0.01047 |    30 |
| ec_elgamal_encrypt               |      4.962 |  ±0.01865 |    60 |
| ec_elgamal_decrypt               |      2.429 | ±0.008477 |    33 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      2.467 |  ±0.01476 |   123 |
| ed25519_sign                     |      1.236 | ±0.006051 |    32 |
| ed25519_verify                   |      4.041 |  ±0.01334 |    33 |
| edwards_dh_keygen                |      2.451 |  ±0.01507 |    50 |
| edwards_dh_agree                 |      1.212 | ±0.005478 |    30 |
| edwards_dh_serialize             |  5.217e-05 | ±2.704e-06 |    30 |
| edwards_elgamal_keygen           |      2.449 |  ±0.00956 |    35 |
| edwards_elgamal_encrypt          |      2.533 | ±0.007652 |    34 |
| edwards_elgamal_decrypt          |      1.912 | ±0.005292 |    49 |

### ML-KEM (Kyber)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.02525 | ±0.000121 |    30 |
| mlkem512_encaps                  |    0.02638 | ±0.0001303 |    60 |
| mlkem512_decaps                  |    0.02974 | ±0.0001262 |    53 |
| mlkem768_keygen                  |    0.04181 | ±0.0002321 |    53 |
| mlkem768_encaps                  |    0.04208 | ±0.0002207 |    35 |
| mlkem768_decaps                  |    0.04714 | ±0.0002718 |    95 |
| mlkem1024_keygen                 |    0.06564 | ±0.000391 |    32 |
| mlkem1024_encaps                 |    0.06401 | ±0.0003192 |    30 |
| mlkem1024_decaps                 |    0.07089 | ±0.0004681 |    30 |

### ML-DSA (Dilithium)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.09466 | ±0.0005698 |    60 |
| mldsa44_sign                     |     0.3145 | ±0.0009198 |    30 |
| mldsa44_verify                   |      0.038 | ±0.0002763 |    31 |
| mldsa65_keygen                   |     0.1683 | ±0.001179 |    35 |
| mldsa65_sign                     |     0.5096 | ±0.002509 |    30 |
| mldsa65_verify                   |    0.05272 | ±0.0003843 |    38 |
| mldsa87_keygen                   |     0.2459 | ±0.001673 |    30 |
| mldsa87_sign                     |     0.6538 | ±0.002697 |    33 |
| mldsa87_verify                   |    0.07554 | ±0.0004726 |    91 |

