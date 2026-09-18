
### Finite-field public key (1024-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_1024                  |      70.84 |    ±4.538 |    50 |
| rsa_encrypt_1024                 |    0.03152 | ±3.491e-05 |    50 |
| rsa_decrypt_1024                 |     0.5262 | ±0.002321 |    50 |
| rsa_sign_1024                    |     0.5287 | ±0.009559 |    50 |
| rsa_verify_1024                  |    0.03129 | ±0.0002794 |    50 |
| elgamal_keygen_1024              |      101.6 |    ±30.58 |  1243 (limit) |
| elgamal_encrypt_1024             |     0.5722 | ±0.0007027 |    50 |
| elgamal_decrypt_1024             |     0.5707 | ±0.001685 |    54 |
| dsa_keygen_1024                  |      116.9 |    ±25.46 |   831 (limit) |
| dsa_sign_1024                    |      0.299 |  ±0.00222 |    51 |
| dsa_verify_1024                  |     0.5752 | ±0.005124 |    55 |
| paillier_keygen_1024             |      66.52 |    ±2.589 |    50 |
| paillier_encrypt_1024            |      8.256 |   ±0.1483 |    50 |
| paillier_decrypt_1024            |      6.484 |  ±0.09507 |    50 |
| paillier_rerandomize_1024        |      6.542 |  ±0.09722 |    50 |
| paillier_add_1024                |    0.02212 | ±0.0003873 |    50 |
| cocks_keygen_1024                |      60.81 |    ±2.081 |    50 |
| cocks_encrypt_1024               |      1.736 |  ±0.01881 |    50 |
| cocks_decrypt_1024               |     0.2464 | ±0.002794 |    50 |
| rabin_keygen_1024                |      83.11 |     ±5.58 |    82 |
| rabin_encrypt_1024               |   0.008019 | ±0.0001483 |   140 |
| rabin_decrypt_1024               |     0.5188 | ±0.009001 |    50 |
| schmidt_samoa_keygen_1024        |      22.39 |   ±0.7031 |    81 |
| schmidt_samoa_encrypt_1024       |      1.725 |  ±0.00316 |    50 |
| schmidt_samoa_decrypt_1024       |     0.5693 | ±0.005995 |    50 |

### RSA (2048-bit)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| rsa_keygen_2048                  |      652.7 |    ±149.7 |   431 (limit) |
| rsa_encrypt_2048                 |     0.1099 | ±0.002679 |    50 |
| rsa_decrypt_2048                 |      3.578 |  ±0.02131 |    50 |
| rsa_sign_2048                    |      3.573 | ±0.004182 |    50 |
| rsa_verify_2048                  |     0.1074 | ±0.0001115 |   110 |

### ECDSA / ECDH (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecdsa_keygen                     |      1.455 |  ±0.02536 |    55 |
| ecdsa_sign                       |      1.444 |  ±0.01255 |    50 |
| ecdsa_verify                     |      2.915 |  ±0.02458 |    50 |
| ecdh_keygen                      |      1.445 |  ±0.01544 |    50 |
| ecdh_agree                       |       1.44 |  ±0.03039 |    50 |
| ecdh_serialize                   |  0.0002236 | ±5.205e-06 |    50 |

### ECIES / EC ElGamal (P-256)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ecies_keygen                     |      1.453 |   ±0.0274 |    50 |
| ecies_encrypt                    |      2.874 |  ±0.04801 |    50 |
| ecies_decrypt                    |      1.435 |  ±0.01021 |    50 |
| ec_elgamal_keygen                |      1.446 |   ±0.0203 |    51 |
| ec_elgamal_encrypt               |      4.355 |  ±0.03258 |    50 |
| ec_elgamal_decrypt               |      4.236 |  ±0.05458 |    50 |

### Ed25519 / Edwards DH / Edwards ElGamal

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ed25519_keygen                   |     0.8327 |  ±0.01452 |    80 |
| ed25519_sign                     |     0.8282 | ±0.009464 |    56 |
| ed25519_verify                   |      1.979 |  ±0.02374 |    50 |
| edwards_dh_keygen                |      1.648 |  ±0.01029 |    50 |
| edwards_dh_agree                 |     0.8296 |  ±0.01354 |    50 |
| edwards_dh_serialize             |  6.336e-05 | ±1.487e-06 |    50 |
| edwards_elgamal_keygen           |      1.675 |  ±0.04462 |    80 |
| edwards_elgamal_encrypt          |      1.771 |  ±0.03868 |    50 |
| edwards_elgamal_decrypt          |      1.392 |  ±0.01458 |    50 |

### X25519 / X448 (RFC 7748)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| x25519_keygen                    |     0.2193 | ±3.633e-05 |   200 |
| x25519_agree                     |     0.2192 | ±0.002929 |   290 |
| x25519_scalar_mult_base          |     0.2193 | ±0.002479 |    50 |
| x25519_scalar_mult               |     0.2185 | ±2.057e-05 |    50 |
| x448_keygen                      |      1.076 |  ±0.01134 |    80 |
| x448_agree                       |      1.072 | ±0.0001152 |   230 |
| x448_scalar_mult_base            |      1.075 |   ±0.0118 |   140 |
| x448_scalar_mult                 |       1.08 |   ±0.0175 |    57 |

### ML-KEM (FIPS 203)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mlkem512_keygen                  |     0.2678 | ±0.0001713 |    80 |
| mlkem512_encaps                  |    0.05945 | ±0.0001419 |    50 |
| mlkem512_decaps                  |     0.0746 | ±0.0001208 |   204 |
| mlkem768_keygen                  |     0.4271 | ±0.001196 |    50 |
| mlkem768_encaps                  |    0.07864 | ±0.0002274 |   174 |
| mlkem768_decaps                  |    0.09907 | ±0.0002195 |    50 |
| mlkem1024_keygen                 |     0.6492 |  ±0.01782 |    50 |
| mlkem1024_encaps                 |     0.1297 | ±0.0007908 |   230 |
| mlkem1024_decaps                 |     0.1288 | ±0.0003208 |   140 |

### ML-DSA (FIPS 204)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| mldsa44_keygen                   |     0.2163 | ±0.0002564 |    83 |
| mldsa44_sign                     |     0.7288 |  ±0.03143 |   110 |
| mldsa44_verify                   |    0.07575 | ±0.0002229 |    50 |
| mldsa65_keygen                   |      0.385 | ±0.0004955 |    50 |
| mldsa65_sign                     |      1.125 |  ±0.05218 |   110 |
| mldsa65_verify                   |     0.1052 | ±0.0003283 |    50 |
| mldsa87_keygen                   |     0.6127 | ±0.000744 |    80 |
| mldsa87_sign                     |       1.18 |  ±0.06751 |    80 |
| mldsa87_verify                   |     0.1545 | ±0.0006319 |   146 |

### NTRU (NIST PQC round 3)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruhps509_keygen                |      3.689 |  ±0.04466 |   145 |
| ntruhps509_encaps                |     0.1439 | ±0.000243 |   620 |
| ntruhps509_decaps                |     0.2577 | ±0.0004326 |    80 |
| ntruhps677_keygen                |      3.333 | ±0.0004348 |    80 |
| ntruhps677_encaps                |     0.1922 | ±0.0003309 |   620 |
| ntruhps677_decaps                |     0.2595 | ±0.0003151 |    50 |
| ntruhps821_keygen                |      5.977 | ±0.002638 |   115 |
| ntruhps821_encaps                |     0.2567 |  ±0.00046 |    85 |
| ntruhps821_decaps                |     0.4345 | ±0.001431 |    50 |
| ntruhrss701_keygen               |      4.035 | ±0.001072 |    50 |
| ntruhrss701_encaps               |     0.1248 | ±0.0003064 |    50 |
| ntruhrss701_decaps               |     0.2985 | ±0.0002326 |   110 |

### NTRUEncrypt (IEEE Std 1363.1-2008)

| Operation                        |   ms/op    | ±CI (90%)  | Runs  |
|----------------------------------|------------|------------|-------|
| ntruees401ep1_keygen             |     0.8404 | ±0.001428 |    52 |
| ntruees401ep1_encrypt            |     0.1745 | ±0.005168 |    50 |
| ntruees401ep1_decrypt            |     0.2877 | ±0.0006532 |    50 |
| ntruees443ep1_keygen             |     0.8674 | ±0.0008467 |    55 |
| ntruees443ep1_encrypt            |    0.04812 | ±0.000345 |    51 |
| ntruees443ep1_decrypt            |    0.07573 | ±0.0004536 |    50 |
| ntruees449ep1_keygen             |      1.046 | ±0.001349 |    80 |
| ntruees449ep1_encrypt            |     0.2541 |  ±0.01469 |    50 |
| ntruees449ep1_decrypt            |     0.3814 | ±0.001281 |   110 |
| ntruees541ep1_keygen             |     0.7641 | ±0.001555 |    50 |
| ntruees541ep1_encrypt            |     0.1028 | ±0.0004595 |   230 |
| ntruees541ep1_decrypt            |     0.1777 | ±0.001108 |    50 |
| ntruees677ep1_keygen             |      1.433 | ±0.001552 |   140 |
| ntruees677ep1_encrypt            |     0.3513 | ±0.0005818 |    80 |
| ntruees677ep1_decrypt            |     0.6391 | ±0.001865 |    50 |
| ntruees1087ep1_keygen            |      1.801 | ±0.002088 |   110 |
| ntruees1087ep1_encrypt           |     0.2237 | ±0.001594 |    80 |
| ntruees1087ep1_decrypt           |     0.4255 | ±0.001437 |    80 |
| ntruees1087ep2_keygen            |      1.897 |  ±0.00293 |    84 |
| ntruees1087ep2_encrypt           |     0.3984 |  ±0.00244 |    50 |
| ntruees1087ep2_decrypt           |     0.7834 | ±0.002712 |    80 |
| ntruees1171ep1_keygen            |      2.254 | ±0.002825 |  1250 |
| ntruees1171ep1_encrypt           |     0.4011 | ±0.003179 |    80 |
| ntruees1171ep1_decrypt           |     0.7468 | ±0.003089 |    57 |
| ntruees1499ep1_keygen            |      4.254 | ±0.005327 |    51 |
| ntruees1499ep1_encrypt           |     0.3812 |  ±0.00372 |    50 |
| ntruees1499ep1_decrypt           |     0.6982 | ±0.002581 |    83 |

