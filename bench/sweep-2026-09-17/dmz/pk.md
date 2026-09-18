
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |         43 |    ±3.241 |    52 |
| rsa_encrypt_1024                 |    0.01624 | ±0.0001133 |    50 |
| rsa_decrypt_1024                 |     0.2875 | ±0.001011 |   110 |
| rsa_sign_1024                    |     0.2893 | ±0.001961 |   110 |
| rsa_verify_1024                  |    0.01627 | ±0.0001978 |    50 |
| elgamal_keygen_1024              |      58.21 |    ±17.09 |  2327 (limit) |
| elgamal_encrypt_1024             |     0.2854 |  ±0.00173 |    50 |
| elgamal_decrypt_1024             |     0.2843 | ±0.004471 |    50 |
| dsa_keygen_1024                  |      59.71 |    ±9.344 |  1605 (limit) |
| dsa_sign_1024                    |     0.1518 | ±0.001521 |    80 |
| dsa_verify_1024                  |     0.2857 | ±0.001529 |    80 |
| paillier_keygen_1024             |      38.14 |     ±2.48 |    53 |
| paillier_encrypt_1024            |      3.983 |  ±0.01101 |    87 |
| paillier_decrypt_1024            |      3.126 |   ±0.0107 |    80 |
| paillier_rerandomize_1024        |      3.153 | ±0.009303 |    50 |
| paillier_add_1024                |    0.01016 | ±7.151e-05 |    50 |
| cocks_keygen_1024                |       34.5 |    ±1.495 |    50 |
| cocks_encrypt_1024               |     0.8586 | ±0.001719 |   260 |
| cocks_decrypt_1024               |     0.1344 | ±0.0003767 |    51 |
| rabin_keygen_1024                |      47.68 |     ±3.14 |    50 |
| rabin_encrypt_1024               |    0.00429 | ±9.026e-05 |    80 |
| rabin_decrypt_1024               |     0.2806 | ±0.0009707 |    50 |
| schmidt_samoa_keygen_1024        |       14.2 |   ±0.4935 |    58 |
| schmidt_samoa_encrypt_1024       |     0.8561 |  ±0.00254 |    50 |
| schmidt_samoa_decrypt_1024       |     0.3024 |  ±0.01323 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      357.2 |    ±73.98 |   850 (limit) |
| rsa_encrypt_2048                 |    0.05312 | ±0.0003177 |   170 |
| rsa_decrypt_2048                 |      1.768 | ±0.003334 |    80 |
| rsa_sign_2048                    |      1.775 |  ±0.01206 |    82 |
| rsa_verify_2048                  |    0.05248 | ±0.0004302 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.9997 | ±0.009314 |    57 |
| ecdsa_sign                       |      1.003 | ±0.006963 |    85 |
| ecdsa_verify                     |      2.012 |   ±0.0133 |    50 |
| ecdh_keygen                      |      1.004 |  ±0.01601 |   320 |
| ecdh_agree                       |     0.9902 |  ±0.01081 |    50 |
| ecdh_serialize                   |  0.0001399 | ±8.228e-06 |    94 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.006 |  ±0.04803 |   140 |
| ecies_encrypt                    |      1.962 |  ±0.02617 |    80 |
| ecies_decrypt                    |     0.9917 |  ±0.00633 |   140 |
| ec_elgamal_keygen                |      0.995 | ±0.008908 |   178 |
| ec_elgamal_encrypt               |       2.99 |  ±0.01701 |    50 |
| ec_elgamal_decrypt               |      2.912 |   ±0.0163 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.4932 | ±0.002516 |   170 |
| ed25519_sign                     |     0.4889 |  ±0.00157 |   112 |
| ed25519_verify                   |      1.207 |  ±0.04742 |    50 |
| edwards_dh_keygen                |     0.9782 | ±0.004717 |    53 |
| edwards_dh_agree                 |     0.4884 | ±0.002878 |   110 |
| edwards_dh_serialize             |  4.926e-05 | ±1.361e-06 |    50 |
| edwards_elgamal_keygen           |     0.9785 | ±0.004101 |    80 |
| edwards_elgamal_encrypt          |      1.039 | ±0.004375 |    50 |
| edwards_elgamal_decrypt          |     0.8457 | ±0.002579 |    85 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.05353 | ±0.0001646 |   230 |
| x25519_agree                     |     0.0534 | ±0.0002378 |    50 |
| x25519_scalar_mult_base          |    0.05287 | ±0.0002485 |    80 |
| x25519_scalar_mult               |    0.05305 | ±0.000246 |    80 |
| x448_keygen                      |     0.4211 | ±0.001211 |   110 |
| x448_agree                       |     0.4194 | ±0.001215 |   140 |
| x448_scalar_mult_base            |     0.4201 | ±0.002044 |    50 |
| x448_scalar_mult                 |     0.4219 | ±0.001834 |   328 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |     0.1871 | ±0.0008895 |    82 |
| mlkem512_encaps                  |    0.04269 | ±0.0002437 |    80 |
| mlkem512_decaps                  |    0.05674 | ±0.0002279 |   200 |
| mlkem768_keygen                  |     0.3002 | ±0.001253 |   260 |
| mlkem768_encaps                  |    0.06158 | ±0.0002377 |   140 |
| mlkem768_decaps                  |    0.07932 | ±0.0001851 |    80 |
| mlkem1024_keygen                 |     0.4507 | ±0.001826 |    80 |
| mlkem1024_encaps                 |     0.1082 | ±0.0006697 |   358 |
| mlkem1024_decaps                 |     0.1234 | ±0.0002595 |    80 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.1429 | ±0.0009877 |   119 |
| mldsa44_sign                     |     0.4862 |  ±0.02274 |    50 |
| mldsa44_verify                   |     0.0537 | ±0.0004983 |    88 |
| mldsa65_keygen                   |     0.2559 | ±0.001288 |    80 |
| mldsa65_sign                     |     0.7712 |  ±0.03275 |    50 |
| mldsa65_verify                   |    0.07649 | ±0.0008272 |    80 |
| mldsa87_keygen                   |     0.3972 | ±0.001913 |    50 |
| mldsa87_sign                     |     0.8101 |  ±0.04629 |    80 |
| mldsa87_verify                   |     0.1162 | ±0.0003239 |   110 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      2.273 | ±0.006223 |    80 |
| ntruhps509_encaps                |     0.1028 | ±0.002729 |    50 |
| ntruhps509_decaps                |     0.1668 | ±0.0005277 |    50 |
| ntruhps677_keygen                |      2.178 | ±0.009497 |   110 |
| ntruhps677_encaps                |     0.1383 | ±0.001108 |   116 |
| ntruhps677_decaps                |     0.1757 |  ±0.00322 |   110 |
| ntruhps821_keygen                |      3.778 |   ±0.0137 |   290 |
| ntruhps821_encaps                |     0.1809 | ±0.001215 |    56 |
| ntruhps821_decaps                |     0.2886 |  ±0.01354 |    50 |
| ntruhrss701_keygen               |      2.594 | ±0.007373 |   143 |
| ntruhrss701_encaps               |    0.08754 | ±0.0007937 |   412 |
| ntruhrss701_decaps               |     0.1988 | ±0.001434 |    80 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.6887 | ±0.001179 |   175 |
| ntruees401ep1_encrypt            |     0.1859 | ±0.006327 |    50 |
| ntruees401ep1_decrypt            |     0.2731 | ±0.008649 |   141 |
| ntruees443ep1_keygen             |     0.6744 | ±0.001221 |    81 |
| ntruees443ep1_encrypt            |    0.03703 | ±0.0002395 |    50 |
| ntruees443ep1_decrypt            |    0.06392 | ±0.0005043 |    50 |
| ntruees449ep1_keygen             |     0.9161 | ±0.001308 |    80 |
| ntruees449ep1_encrypt            |     0.1897 |  ±0.01125 |    50 |
| ntruees449ep1_decrypt            |     0.2983 | ±0.001335 |   140 |
| ntruees541ep1_keygen             |     0.6865 | ±0.001502 |    81 |
| ntruees541ep1_encrypt            |    0.07362 | ±0.0004721 |   171 |
| ntruees541ep1_decrypt            |     0.1631 | ±0.001077 |    50 |
| ntruees677ep1_keygen             |      1.201 | ±0.001724 |    50 |
| ntruees677ep1_encrypt            |     0.2973 | ±0.0008163 |   200 |
| ntruees677ep1_decrypt            |     0.5705 |  ±0.00425 |   170 |
| ntruees1087ep1_keygen            |      1.516 | ±0.006869 |   110 |
| ntruees1087ep1_encrypt           |     0.1931 | ±0.002727 |    53 |
| ntruees1087ep1_decrypt           |     0.3882 | ±0.003003 |    50 |
| ntruees1087ep2_keygen            |      1.638 | ±0.005439 |   170 |
| ntruees1087ep2_encrypt           |     0.3456 | ±0.002335 |    54 |
| ntruees1087ep2_decrypt           |     0.7466 | ±0.003554 |    50 |
| ntruees1171ep1_keygen            |      1.882 |  ±0.01217 |    50 |
| ntruees1171ep1_encrypt           |     0.3446 | ±0.001458 |    80 |
| ntruees1171ep1_decrypt           |     0.7648 | ±0.004506 |    50 |
| ntruees1499ep1_keygen            |      3.138 |  ±0.03615 |   140 |
| ntruees1499ep1_encrypt           |     0.3272 | ±0.007406 |    50 |
| ntruees1499ep1_decrypt           |     0.5475 | ±0.004155 |   170 |

