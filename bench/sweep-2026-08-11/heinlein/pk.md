
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      62.49 |   ±0.2912 |    50 |
| rsa_encrypt_1024                 |    0.02056 | ±2.636e-05 |    82 |
| rsa_decrypt_1024                 |      0.337 | ±0.0005036 |   110 |
| rsa_sign_1024                    |     0.3364 | ±0.0005865 |    80 |
| rsa_verify_1024                  |    0.02097 | ±1.722e-05 |    80 |
| elgamal_keygen_1024              |      112.3 |   ±0.4498 |    50 |
| elgamal_encrypt_1024             |     0.5472 | ±0.0005604 |    50 |
| elgamal_decrypt_1024             |     0.2721 | ±0.0001705 |    50 |
| dsa_keygen_1024                  |      80.61 |   ±0.3098 |    50 |
| dsa_sign_1024                    |     0.3218 | ±0.0002066 |    50 |
| dsa_verify_1024                  |     0.5831 | ±0.0004643 |    50 |
| paillier_keygen_1024             |      42.53 |   ±0.1171 |    50 |
| paillier_encrypt_1024            |      5.342 |  ±0.02866 |    57 |
| paillier_decrypt_1024            |      4.006 |   ±0.0257 |    50 |
| paillier_rerandomize_1024        |       4.13 |  ±0.01559 |    50 |
| paillier_add_1024                |    0.02156 | ±0.0003708 |    50 |
| cocks_keygen_1024                |      38.46 |   ±0.1417 |    50 |
| cocks_encrypt_1024               |      1.257 |  ±0.00613 |    50 |
| cocks_decrypt_1024               |     0.1586 | ±0.0006257 |    50 |
| rabin_keygen_1024                |      44.87 |    ±0.169 |    50 |
| rabin_encrypt_1024               |   0.005968 | ±4.322e-05 |   110 |
| rabin_decrypt_1024               |     0.3448 | ±0.004771 |    50 |
| schmidt_samoa_keygen_1024        |      17.41 |   ±0.2047 |   140 |
| schmidt_samoa_encrypt_1024       |      1.322 | ±0.005045 |    50 |
| schmidt_samoa_decrypt_1024       |     0.3704 | ±0.001875 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      642.2 |   ±0.7072 |    50 |
| rsa_encrypt_2048                 |    0.06935 | ±6.586e-05 |    50 |
| rsa_decrypt_2048                 |      2.203 | ±0.001736 |    52 |
| rsa_sign_2048                    |      2.204 | ±0.001965 |    50 |
| rsa_verify_2048                  |    0.06941 | ±6.195e-05 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      1.013 |  ±0.00425 |    50 |
| ecdsa_sign                       |      1.049 | ±0.001983 |    88 |
| ecdsa_verify                     |      2.032 | ±0.006031 |    57 |
| ecdh_keygen                      |      1.015 | ±0.002807 |    50 |
| ecdh_agree                       |     0.9976 | ±0.002104 |    50 |
| ecdh_serialize                   |  0.0001734 | ±1.329e-05 |   202 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.015 | ±0.003916 |    50 |
| ecies_encrypt                    |       2.01 | ±0.006467 |    50 |
| ecies_decrypt                    |      1.043 | ±0.006307 |    80 |
| ec_elgamal_keygen                |      1.014 | ±0.003035 |    53 |
| ec_elgamal_encrypt               |      2.117 |  ±0.00688 |    50 |
| ec_elgamal_decrypt               |       1.07 | ±0.004876 |   179 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |      1.202 | ±0.001979 |    50 |
| ed25519_sign                     |     0.5984 | ±0.004293 |    50 |
| ed25519_verify                   |      1.885 | ±0.003486 |    54 |
| edwards_dh_keygen                |      1.171 | ±0.004122 |   140 |
| edwards_dh_agree                 |     0.5899 | ±0.001329 |    50 |
| edwards_dh_serialize             |  8.984e-05 | ±7.406e-06 |   516 |
| edwards_elgamal_keygen           |      1.171 | ±0.003214 |   110 |
| edwards_elgamal_encrypt          |      1.264 | ±0.006536 |    50 |
| edwards_elgamal_decrypt          |      1.032 | ±0.004787 |    80 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.09355 | ±0.001335 |   110 |
| x25519_agree                     |    0.09251 | ±0.001412 |    50 |
| x25519_scalar_mult_base          |    0.09293 | ±0.001243 |    50 |
| x25519_scalar_mult               |    0.09223 | ±0.001218 |    80 |
| x448_keygen                      |     0.5539 | ±0.004547 |   110 |
| x448_agree                       |     0.5468 | ±0.004638 |    50 |
| x448_scalar_mult_base            |     0.5543 | ±0.005977 |    83 |
| x448_scalar_mult                 |     0.5531 | ±0.004619 |    50 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |    0.04194 | ±0.003268 |   831 |
| mlkem512_encaps                  |    0.03105 | ±0.002565 |   565 |
| mlkem512_decaps                  |    0.03444 | ±0.002122 |  1190 |
| mlkem768_keygen                  |    0.07032 |  ±0.00586 |   717 |
| mlkem768_encaps                  |    0.04245 | ±0.003537 |  1469 |
| mlkem768_decaps                  |    0.04795 | ±0.004002 |   839 |
| mlkem1024_keygen                 |       0.11 | ±0.008793 |   320 |
| mlkem1024_encaps                 |    0.05832 | ±0.004074 |   560 |
| mlkem1024_decaps                 |    0.06589 |  ±0.00413 |   835 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.1705 |  ±0.01357 |    80 |
| mldsa44_sign                     |      0.471 |    ±0.034 |    50 |
| mldsa44_verify                   |    0.05488 | ±0.004006 |   530 |
| mldsa65_keygen                   |      0.291 |  ±0.02428 |    59 |
| mldsa65_sign                     |     0.7905 |  ±0.03576 |    50 |
| mldsa65_verify                   |    0.07849 | ±0.006465 |   263 |
| mldsa87_keygen                   |     0.4118 |  ±0.03407 |    55 |
| mldsa87_sign                     |     0.5075 |  ±0.02972 |    50 |
| mldsa87_verify                   |     0.1144 | ±0.004208 |   260 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |       2.56 |  ±0.03695 |    50 |
| ntruhps509_encaps                |     0.2252 |  ±0.01171 |    50 |
| ntruhps509_decaps                |     0.3502 | ±0.005051 |    80 |
| ntruhps677_keygen                |      3.382 |  ±0.03239 |   110 |
| ntruhps677_encaps                |     0.2623 | ±0.003471 |    50 |
| ntruhps677_decaps                |     0.3432 |  ±0.02239 |    50 |
| ntruhps821_keygen                |      5.398 |  ±0.08901 |    54 |
| ntruhps821_encaps                |     0.3856 |  ±0.02795 |    50 |
| ntruhps821_decaps                |      0.599 |  ±0.04948 |    50 |
| ntruhrss701_keygen               |      3.698 |  ±0.04872 |    80 |
| ntruhrss701_encaps               |     0.1468 |  ±0.00231 |    50 |
| ntruhrss701_decaps               |     0.3748 | ±0.004132 |    50 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |      1.831 |  ±0.04926 |   110 |
| ntruees401ep1_encrypt            |     0.2963 |  ±0.02016 |    50 |
| ntruees401ep1_decrypt            |     0.4827 |  ±0.03273 |    80 |
| ntruees443ep1_keygen             |      1.712 |  ±0.02397 |    80 |
| ntruees443ep1_encrypt            |     0.1017 | ±0.007294 |   140 |
| ntruees443ep1_decrypt            |     0.1371 |   ±0.0113 |   116 |
| ntruees449ep1_keygen             |      2.184 |  ±0.05105 |    50 |
| ntruees449ep1_encrypt            |     0.4387 |  ±0.02869 |    50 |
| ntruees449ep1_decrypt            |     0.6227 |  ±0.05111 |    53 |
| ntruees541ep1_keygen             |      1.962 |   ±0.1165 |    50 |
| ntruees541ep1_encrypt            |     0.1971 |  ±0.01619 |    83 |
| ntruees541ep1_decrypt            |     0.3105 |  ±0.02535 |    80 |
| ntruees677ep1_keygen             |      3.337 |   ±0.2777 |    53 |
| ntruees677ep1_encrypt            |     0.5875 |  ±0.02286 |    50 |
| ntruees677ep1_decrypt            |      1.023 |  ±0.01056 |    80 |
| ntruees1087ep1_keygen            |      5.066 |   ±0.1294 |    50 |
| ntruees1087ep1_encrypt           |     0.4467 | ±0.005431 |    50 |
| ntruees1087ep1_decrypt           |     0.7537 |  ±0.01328 |    80 |
| ntruees1087ep2_keygen            |      5.416 |   ±0.2621 |    50 |
| ntruees1087ep2_encrypt           |     0.7621 | ±0.009195 |    50 |
| ntruees1087ep2_decrypt           |       1.37 |  ±0.01687 |    52 |
| ntruees1171ep1_keygen            |      6.106 |   ±0.4724 |    50 |
| ntruees1171ep1_encrypt           |     0.7426 |  ±0.04789 |    50 |
| ntruees1171ep1_decrypt           |      1.289 |  ±0.02434 |    50 |
| ntruees1499ep1_keygen            |      9.638 |   ±0.1622 |   290 |
| ntruees1499ep1_encrypt           |     0.7198 |  ±0.01159 |    51 |
| ntruees1499ep1_decrypt           |       1.27 |  ±0.01801 |    80 |

