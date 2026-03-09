
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      14.66 |   ±0.0793 |    90 |
| rsa_encrypt_1024                 |    0.03122 | ±0.0002236 |    30 |
| rsa_decrypt_1024                 |     0.2465 |  ±0.00371 |    44 |
| rsa_sign_1024                    |     0.2431 | ±0.002273 |    38 |
| rsa_verify_1024                  |    0.03202 | ±0.0009226 |    30 |
| elgamal_keygen_1024              |       48.6 |   ±0.9629 |    90 |
| elgamal_encrypt_1024             |     0.3472 |  ±0.01123 |    31 |
| elgamal_decrypt_1024             |     0.1764 | ±0.005602 |    31 |
| dsa_keygen_1024                  |      52.23 |    ±0.328 |    30 |
| dsa_sign_1024                    |     0.2662 | ±0.002421 |    30 |
| dsa_verify_1024                  |      0.409 | ±0.001662 |    49 |
| paillier_keygen_1024             |      16.02 |   ±0.2481 |    92 |
| paillier_encrypt_1024            |      6.014 |  ±0.02396 |   153 |
| paillier_decrypt_1024            |      2.154 |  ±0.01687 |    30 |
| paillier_rerandomize_1024        |      3.875 |  ±0.05316 |    30 |
| paillier_add_1024                |   0.006705 | ±3.593e-05 |   120 |
| cocks_keygen_1024                |       12.1 |   ±0.1091 |    30 |
| cocks_encrypt_1024               |     0.7823 |  ±0.06647 |    41 |
| cocks_decrypt_1024               |      0.128 | ±0.001349 |    60 |
| rabin_keygen_1024                |       20.7 |   ±0.2649 |    32 |
| rabin_encrypt_1024               |    0.02713 | ±0.0004221 |    30 |
| rabin_decrypt_1024               |     0.2524 | ±0.003722 |    32 |
| schmidt_samoa_keygen_1024        |      5.243 |  ±0.06046 |    35 |
| schmidt_samoa_encrypt_1024       |     0.7884 |  ±0.01059 |    36 |
| schmidt_samoa_decrypt_1024       |     0.2163 |  ±0.02033 |    30 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      163.6 |     ±1.27 |   138 |
| rsa_encrypt_2048                 |     0.1031 | ±0.002526 |    30 |
| rsa_decrypt_2048                 |       1.53 |  ±0.02579 |    30 |
| rsa_sign_2048                    |       1.53 |  ±0.02604 |    31 |
| rsa_verify_2048                  |     0.1049 | ±0.002369 |    90 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      1.729 |  ±0.01064 |   126 |
| ecdsa_sign                       |      1.864 |  ±0.01145 |    90 |
| ecdsa_verify                     |      3.543 |    ±0.018 |    30 |
| ecdh_keygen                      |      1.738 | ±0.008593 |    30 |
| ecdh_agree                       |      1.789 | ±0.007137 |    33 |
| ecdh_serialize                   |   7.34e-05 | ±2.622e-06 |    47 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.743 |  ±0.01122 |    30 |
| ecies_encrypt                    |      3.467 |  ±0.03362 |    60 |
| ecies_decrypt                    |      1.703 | ±0.007077 |    90 |
| ec_elgamal_keygen                |      1.737 | ±0.006457 |   132 |
| ec_elgamal_encrypt               |      3.554 |  ±0.01666 |    60 |
| ec_elgamal_decrypt               |      1.834 |  ±0.02305 |    90 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      1.712 | ±0.008143 |    60 |
| ed25519_sign                     |     0.8694 | ±0.007153 |    30 |
| ed25519_verify                   |      2.844 |   ±0.0204 |    30 |
| edwards_dh_keygen                |      1.713 |   ±0.0115 |    30 |
| edwards_dh_agree                 |     0.8591 |   ±0.0119 |    30 |
| edwards_dh_serialize             |  5.541e-05 | ±1.764e-06 |   167 |
| edwards_elgamal_keygen           |      1.718 |  ±0.01146 |    30 |
| edwards_elgamal_encrypt          |      1.793 |  ±0.01397 |    60 |
| edwards_elgamal_decrypt          |      1.332 | ±0.009984 |   102 |

### ML-KEM (Kyber)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.01718 | ±0.000234 |    30 |
| mlkem512_encaps                  |    0.01672 | ±0.001943 |    64 |
| mlkem512_decaps                  |    0.01643 | ±0.0001751 |    68 |
| mlkem768_keygen                  |    0.02793 | ±0.0002995 |   103 |
| mlkem768_encaps                  |    0.02669 | ±0.0003204 |   192 |
| mlkem768_decaps                  |    0.02721 | ±0.0003639 |    30 |
| mlkem1024_keygen                 |     0.0444 | ±0.0006144 |    30 |
| mlkem1024_encaps                 |    0.04177 | ±0.000618 |   120 |
| mlkem1024_decaps                 |    0.04266 | ±0.0006011 |    60 |

### ML-DSA (Dilithium)

| Operation                        |   ms/op    | ±CI (95%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.06451 | ±0.0004568 |    63 |
| mldsa44_sign                     |     0.1119 |  ±0.00051 |    30 |
| mldsa44_verify                   |    0.01292 | ±0.0001693 |    44 |
| mldsa65_keygen                   |     0.1205 | ±0.0007272 |    95 |
| mldsa65_sign                     |     0.1706 | ±0.0008673 |    30 |
| mldsa65_verify                   |    0.01695 | ±0.0003647 |    60 |
| mldsa87_keygen                   |     0.1814 | ±0.0009118 |    33 |
| mldsa87_sign                     |     0.2232 |  ±0.01663 |    36 |
| mldsa87_verify                   |    0.02451 | ±0.0004441 |    30 |

