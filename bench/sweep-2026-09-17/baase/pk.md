
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      20.42 |      ±1.6 |    53 |
| rsa_encrypt_1024                 |   0.009443 | ±0.0007801 |    89 |
| rsa_decrypt_1024                 |     0.1321 | ±0.007622 |    50 |
| rsa_sign_1024                    |     0.1281 | ±0.0002746 |    50 |
| rsa_verify_1024                  |   0.008909 | ±4.995e-05 |    50 |
| elgamal_keygen_1024              |      30.32 |    ±9.278 |  4245 (limit) |
| elgamal_encrypt_1024             |     0.1495 |  ±0.01058 |   200 |
| elgamal_decrypt_1024             |     0.1478 |  ±0.01229 |    54 |
| dsa_keygen_1024                  |      30.96 |    ±6.551 |  2868 (limit) |
| dsa_sign_1024                    |    0.07792 | ±0.004707 |    50 |
| dsa_verify_1024                  |     0.1461 |  ±0.01066 |    50 |
| paillier_keygen_1024             |      19.78 |   ±0.9909 |    53 |
| paillier_encrypt_1024            |      2.188 |  ±0.02521 |    50 |
| paillier_decrypt_1024            |      1.713 |  ±0.04414 |    50 |
| paillier_rerandomize_1024        |      1.728 | ±0.003801 |    50 |
| paillier_add_1024                |   0.005912 | ±1.982e-05 |    80 |
| cocks_keygen_1024                |       17.6 |    ±1.016 |    50 |
| cocks_encrypt_1024               |     0.4296 | ±0.003012 |    50 |
| cocks_decrypt_1024               |     0.0576 | ±0.0003874 |    80 |
| rabin_keygen_1024                |      25.82 |    ±1.994 |    50 |
| rabin_encrypt_1024               |   0.002482 | ±9.103e-05 |    80 |
| rabin_decrypt_1024               |     0.1239 | ±0.0002735 |    50 |
| schmidt_samoa_keygen_1024        |        7.6 |   ±0.5851 |    85 |
| schmidt_samoa_encrypt_1024       |     0.4522 |  ±0.01941 |    50 |
| schmidt_samoa_decrypt_1024       |     0.1491 | ±0.007306 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      179.3 |    ±39.92 |  1626 (limit) |
| rsa_encrypt_2048                 |     0.0309 | ±4.758e-05 |    82 |
| rsa_decrypt_2048                 |     0.9003 | ±0.002201 |    50 |
| rsa_sign_2048                    |     0.8998 | ±0.001308 |    85 |
| rsa_verify_2048                  |    0.03042 | ±4.763e-05 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.4921 |  ±0.01129 |   170 |
| ecdsa_sign                       |     0.4939 |  ±0.01299 |   140 |
| ecdsa_verify                     |     0.9684 |  ±0.07068 |    50 |
| ecdh_keygen                      |     0.4855 |  ±0.03488 |   113 |
| ecdh_agree                       |     0.4786 |  ±0.01194 |    50 |
| ecdh_serialize                   |   7.68e-05 | ±1.067e-06 |   140 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |     0.4961 |  ±0.01202 |    50 |
| ecies_encrypt                    |     0.9768 |  ±0.02333 |    50 |
| ecies_decrypt                    |      0.505 |  ±0.02291 |    50 |
| ec_elgamal_keygen                |     0.4906 |  ±0.03389 |    50 |
| ec_elgamal_encrypt               |       1.49 |  ±0.07167 |   110 |
| ec_elgamal_decrypt               |      1.414 |  ±0.02652 |   110 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.2683 | ±0.003251 |    80 |
| ed25519_sign                     |     0.2636 | ±0.004634 |   260 |
| ed25519_verify                   |     0.6503 | ±0.009822 |    54 |
| edwards_dh_keygen                |     0.5239 | ±0.004858 |   110 |
| edwards_dh_agree                 |     0.2794 |  ±0.02325 |    55 |
| edwards_dh_serialize             |  2.437e-05 | ±2.026e-06 |   123 |
| edwards_elgamal_keygen           |     0.5507 |  ±0.01294 |    50 |
| edwards_elgamal_encrypt          |     0.6182 |  ±0.05141 |    82 |
| edwards_elgamal_decrypt          |     0.4479 |  ±0.01768 |   140 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.02921 | ±0.002307 |    50 |
| x25519_agree                     |     0.0283 |  ±0.00163 |   260 |
| x25519_scalar_mult_base          |    0.02831 | ±0.001631 |    50 |
| x25519_scalar_mult               |    0.02908 | ±0.002395 |   298 |
| x448_keygen                      |     0.1972 |  ±0.01283 |    59 |
| x448_agree                       |     0.1869 | ±0.0001616 |  1790 |
| x448_scalar_mult_base            |     0.1867 | ±0.0001127 |   290 |
| x448_scalar_mult                 |     0.1969 |  ±0.01452 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.06768 | ±8.45e-05 |    80 |
| mlkem512_encaps                  |    0.01405 | ±9.193e-05 |   380 |
| mlkem512_decaps                  |     0.0183 | ±0.001454 |   230 |
| mlkem768_keygen                  |     0.1127 | ±0.007714 |   140 |
| mlkem768_encaps                  |    0.01863 | ±0.000168 |   170 |
| mlkem768_decaps                  |    0.02464 | ±0.001892 |    82 |
| mlkem1024_keygen                 |     0.1726 |  ±0.01085 |    80 |
| mlkem1024_encaps                 |    0.02486 | ±0.002023 |    80 |
| mlkem1024_decaps                 |    0.03143 | ±0.0002111 |    80 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.04558 | ±0.003758 |    89 |
| mldsa44_sign                     |     0.1595 |  ±0.00639 |   170 |
| mldsa44_verify                   |    0.01765 | ±0.0002555 |    80 |
| mldsa65_keygen                   |    0.08235 | ±0.004982 |    85 |
| mldsa65_sign                     |     0.2521 |  ±0.01287 |   110 |
| mldsa65_verify                   |    0.02471 | ±0.0002269 |   200 |
| mldsa87_keygen                   |     0.1195 |  ±0.00793 |    82 |
| mldsa87_sign                     |     0.2602 |  ±0.01361 |    80 |
| mldsa87_verify                   |      0.036 | ±0.002789 |   110 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      1.176 |  ±0.03927 |    50 |
| ntruhps509_encaps                |    0.04606 | ±0.000221 |   350 |
| ntruhps509_decaps                |    0.08181 | ±0.005714 |   380 |
| ntruhps677_keygen                |       1.04 | ±0.0004504 |    80 |
| ntruhps677_encaps                |    0.06004 | ±0.004047 |    50 |
| ntruhps677_decaps                |    0.08065 | ±0.006574 |   140 |
| ntruhps821_keygen                |      1.885 |   ±0.1254 |    50 |
| ntruhps821_encaps                |    0.07959 | ±0.0003806 |   350 |
| ntruhps821_decaps                |     0.1324 |  ±0.00816 |   593 |
| ntruhrss701_keygen               |      1.263 | ±0.001043 |   230 |
| ntruhrss701_encaps               |    0.04117 | ±0.002256 |   200 |
| ntruhrss701_decaps               |    0.09187 | ±0.005147 |   170 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.3487 |  ±0.01619 |   200 |
| ntruees401ep1_encrypt            |     0.0585 | ±0.004474 |    80 |
| ntruees401ep1_decrypt            |    0.09865 | ±0.007037 |    80 |
| ntruees443ep1_keygen             |     0.3319 | ±0.0003822 |   110 |
| ntruees443ep1_encrypt            |     0.0171 | ±0.0002855 |   115 |
| ntruees443ep1_decrypt            |    0.02665 | ±0.002204 |   388 |
| ntruees449ep1_keygen             |      0.441 |  ±0.03344 |    50 |
| ntruees449ep1_encrypt            |    0.08333 | ±0.005972 |   200 |
| ntruees449ep1_decrypt            |      0.121 | ±0.006894 |    50 |
| ntruees541ep1_keygen             |     0.4069 |  ±0.02818 |   176 |
| ntruees541ep1_encrypt            |    0.03321 | ±0.001745 |    86 |
| ntruees541ep1_decrypt            |    0.05759 | ±0.004498 |    50 |
| ntruees677ep1_keygen             |     0.6008 |  ±0.04595 |   230 |
| ntruees677ep1_encrypt            |     0.1052 |  ±0.00866 |   115 |
| ntruees677ep1_decrypt            |     0.2185 |  ±0.01801 |   202 |
| ntruees1087ep1_keygen            |      1.171 |  ±0.09561 |    80 |
| ntruees1087ep1_encrypt           |    0.07491 |  ±0.00362 |   178 |
| ntruees1087ep1_decrypt           |     0.1352 | ±0.007618 |   170 |
| ntruees1087ep2_keygen            |      1.033 |   ±0.0843 |    56 |
| ntruees1087ep2_encrypt           |     0.1359 |  ±0.01081 |   200 |
| ntruees1087ep2_decrypt           |     0.2521 |  ±0.01964 |    80 |
| ntruees1171ep1_keygen            |      1.041 |  ±0.06569 |   110 |
| ntruees1171ep1_encrypt           |     0.1354 | ±0.006482 |   140 |
| ntruees1171ep1_decrypt           |     0.2515 |  ±0.02092 |    81 |
| ntruees1499ep1_keygen            |      1.548 |  ±0.06714 |   143 |
| ntruees1499ep1_encrypt           |     0.1307 |  ±0.00626 |    80 |
| ntruees1499ep1_decrypt           |     0.2431 |  ±0.02006 |   599 |

