
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      15.41 |  ±0.03393 |    80 |
| rsa_encrypt_1024                 |    0.04398 | ±9.542e-05 |    80 |
| rsa_decrypt_1024                 |     0.2865 |  ±0.00137 |    50 |
| rsa_sign_1024                    |     0.2888 | ±0.007068 |    50 |
| rsa_verify_1024                  |    0.04397 | ±7.682e-05 |   269 |
| elgamal_keygen_1024              |      76.61 |     ±3.39 |    88 |
| elgamal_encrypt_1024             |     0.3607 | ±0.003482 |   140 |
| elgamal_decrypt_1024             |      0.182 | ±0.001355 |    50 |
| dsa_keygen_1024                  |      52.59 |   ±0.3502 |   866 |
| dsa_sign_1024                    |     0.3326 | ±0.002045 |   170 |
| dsa_verify_1024                  |     0.4941 | ±0.005997 |    50 |
| paillier_keygen_1024             |      16.93 |   ±0.4835 |    50 |
| paillier_encrypt_1024            |      7.536 |   ±0.1951 |    51 |
| paillier_decrypt_1024            |      2.526 |   ±0.0772 |   110 |
| paillier_rerandomize_1024        |      4.605 |  ±0.02404 |   110 |
| paillier_add_1024                |    0.01299 | ±9.32e-05 |    50 |
| cocks_keygen_1024                |      13.05 |   ±0.2719 |    50 |
| cocks_encrypt_1024               |     0.8327 | ±0.003166 |   290 |
| cocks_decrypt_1024               |     0.1513 | ±0.005984 |    50 |
| rabin_keygen_1024                |      18.76 |   ±0.5245 |    50 |
| rabin_encrypt_1024               |    0.03731 | ±7.549e-05 |   170 |
| rabin_decrypt_1024               |     0.2819 | ±0.001538 |    50 |
| schmidt_samoa_keygen_1024        |      6.729 |  ±0.03425 |   110 |
| schmidt_samoa_encrypt_1024       |     0.8208 | ±0.008108 |    50 |
| schmidt_samoa_decrypt_1024       |     0.2255 |  ±0.00557 |    53 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |        254 |    ±3.275 |    87 |
| rsa_encrypt_2048                 |      0.134 | ±0.001233 |    50 |
| rsa_decrypt_2048                 |      1.547 | ±0.009052 |   140 |
| rsa_sign_2048                    |      1.555 |   ±0.0141 |    52 |
| rsa_verify_2048                  |      0.133 | ±0.0004885 |    50 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |     0.8017 | ±0.001301 |    80 |
| ecdsa_sign                       |     0.9418 | ±0.001527 |    51 |
| ecdsa_verify                     |      1.716 |  ±0.06061 |    50 |
| ecdh_keygen                      |     0.8052 | ±0.003843 |   110 |
| ecdh_agree                       |     0.8182 | ±0.004945 |   110 |
| ecdh_serialize                   |  0.0001066 | ±2.348e-06 |    59 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      0.807 | ±0.005474 |    58 |
| ecies_encrypt                    |      1.584 |   ±0.0106 |   170 |
| ecies_decrypt                    |     0.7902 | ±0.002498 |   110 |
| ec_elgamal_keygen                |     0.8048 | ±0.006631 |   200 |
| ec_elgamal_encrypt               |      1.697 | ±0.008288 |    50 |
| ec_elgamal_decrypt               |     0.8196 | ±0.001801 |   110 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.7972 | ±0.004956 |    50 |
| ed25519_sign                     |     0.4173 | ±0.001633 |   200 |
| ed25519_verify                   |      1.373 | ±0.008821 |   320 |
| edwards_dh_keygen                |     0.7866 | ±0.006858 |    80 |
| edwards_dh_agree                 |     0.4047 | ±0.004463 |   141 |
| edwards_dh_serialize             |  7.674e-05 | ±2.068e-06 |    50 |
| edwards_elgamal_keygen           |     0.7889 | ±0.008716 |   140 |
| edwards_elgamal_encrypt          |     0.9602 |  ±0.01177 |   140 |
| edwards_elgamal_decrypt          |      0.823 |  ±0.01175 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |    0.03604 | ±0.001126 |   140 |
| x25519_agree                     |    0.03474 | ±0.0008076 |   410 |
| x25519_scalar_mult_base          |     0.0385 | ±0.001985 |   834 |
| x25519_scalar_mult               |    0.03465 | ±0.0003797 |  1105 |
| x448_keygen                      |     0.2543 | ±0.007838 |  1940 |
| x448_agree                       |     0.2522 |   ±0.0108 |   200 |
| x448_scalar_mult_base            |     0.2439 | ±0.006389 |   200 |
| x448_scalar_mult                 |     0.2426 | ±0.005196 |    88 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |     0.0232 | ±0.001917 |   204 |
| mlkem512_encaps                  |    0.01991 | ±0.0001865 |   950 |
| mlkem512_decaps                  |    0.02236 | ±0.001313 |    54 |
| mlkem768_keygen                  |    0.03501 |   ±0.0005 |    58 |
| mlkem768_encaps                  |    0.03278 | ±0.0004288 |   680 |
| mlkem768_decaps                  |    0.03685 | ±0.002925 |    50 |
| mlkem1024_keygen                 |    0.05438 | ±0.0005956 |   200 |
| mlkem1024_encaps                 |    0.05093 | ±0.0007107 |    50 |
| mlkem1024_decaps                 |    0.05839 | ±0.004873 |    58 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |    0.08007 | ±0.001451 |    50 |
| mldsa44_sign                     |     0.1827 | ±0.0001737 |   380 |
| mldsa44_verify                   |     0.0221 | ±0.001814 |  1104 |
| mldsa65_keygen                   |      0.173 |  ±0.01275 |   110 |
| mldsa65_sign                     |     0.3319 | ±0.001631 |   110 |
| mldsa65_verify                   |    0.03086 | ±0.001426 |    51 |
| mldsa87_keygen                   |     0.2403 | ±0.004249 |   682 |
| mldsa87_sign                     |      0.214 | ±0.002686 |   110 |
| mldsa87_verify                   |    0.04784 | ±0.0003287 |    50 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |       1.01 |  ±0.03758 |   140 |
| ntruhps509_encaps                |    0.08523 | ±0.003333 |   140 |
| ntruhps509_decaps                |      0.156 |  ±0.01196 |    51 |
| ntruhps677_keygen                |      1.127 |  ±0.01347 |   140 |
| ntruhps677_encaps                |     0.1025 | ±0.003655 |   261 |
| ntruhps677_decaps                |     0.1153 | ±0.002463 |    89 |
| ntruhps821_keygen                |      2.478 |  ±0.09013 |    50 |
| ntruhps821_encaps                |     0.1631 | ±0.0006477 |   110 |
| ntruhps821_decaps                |     0.2954 | ±0.001446 |    50 |
| ntruhrss701_keygen               |      1.189 |  ±0.03097 |    50 |
| ntruhrss701_encaps               |    0.04695 | ±0.0008647 |    80 |
| ntruhrss701_decaps               |     0.1205 | ±0.002692 |   110 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.7687 | ±0.004918 |   320 |
| ntruees401ep1_encrypt            |     0.1026 | ±0.001495 |   440 |
| ntruees401ep1_decrypt            |     0.1517 |  ±0.00516 |    80 |
| ntruees443ep1_keygen             |     0.7239 | ±0.005272 |   140 |
| ntruees443ep1_encrypt            |      0.042 | ±0.0008745 |    50 |
| ntruees443ep1_decrypt            |    0.04088 | ±0.0005983 |    50 |
| ntruees449ep1_keygen             |      0.912 | ±0.008829 |   110 |
| ntruees449ep1_encrypt            |     0.1418 | ±0.001775 |    50 |
| ntruees449ep1_decrypt            |     0.1787 | ±0.005028 |   110 |
| ntruees541ep1_keygen             |      0.709 |  ±0.00574 |   416 |
| ntruees541ep1_encrypt            |    0.07116 | ±0.0007611 |   147 |
| ntruees541ep1_decrypt            |    0.08589 | ±0.0009115 |   110 |
| ntruees677ep1_keygen             |      1.152 |  ±0.00981 |    51 |
| ntruees677ep1_encrypt            |     0.1742 | ±0.001373 |    50 |
| ntruees677ep1_decrypt            |     0.2705 | ±0.002719 |   560 |
| ntruees1087ep1_keygen            |        1.8 |  ±0.01178 |   170 |
| ntruees1087ep1_encrypt           |     0.1417 | ±0.008618 |   140 |
| ntruees1087ep1_decrypt           |     0.1856 | ±0.002178 |    50 |
| ntruees1087ep2_keygen            |        1.9 |  ±0.04097 |    50 |
| ntruees1087ep2_encrypt           |     0.2161 | ±0.003448 |    80 |
| ntruees1087ep2_decrypt           |     0.3254 | ±0.001143 |   320 |
| ntruees1171ep1_keygen            |      2.046 | ±0.007211 |    53 |
| ntruees1171ep1_encrypt           |     0.2074 | ±0.001882 |    53 |
| ntruees1171ep1_decrypt           |     0.3097 | ±0.0002768 |   170 |
| ntruees1499ep1_keygen            |      3.604 |   ±0.2413 |    50 |
| ntruees1499ep1_encrypt           |     0.2132 | ±0.001169 |    89 |
| ntruees1499ep1_decrypt           |     0.3157 |  ±0.02472 |    50 |

