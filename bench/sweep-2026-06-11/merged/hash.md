### MD5 / SHA-1 / RIPEMD-160 (legacy)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| md5 | 128 | 206.5 | ±0.8391 | 207 | 360.7 | ±5.679 | 50 | 115.2 | ±9.586 | 3265 |
| sha1 | 160 | 182 | ±0.8126 | 200 | 275.1 | ±3.627 | 56 | 152.6 | ±9.664 | 800 |
| ripemd160 | 160 | 212.2 | ±0.6193 | 800 | 161.9 | ±1.378 | 80 | 95.99 | ±4.79 | 55 |

### SHA-2 (FIPS 180-4)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| sha224 | 224 | 193.6 | ±0.5624 | 890 | 206 | ±1.588 | 80 | 96.93 | ±7.222 | 4734 |
| sha256 | 256 | 193.7 | ±0.3768 | 770 | 206.1 | ±3.116 | 80 | 97.1 | ±6.566 | 5873 |
| sha384 | 384 | 238.9 | ±0.1269 | 475 | 318.8 | ±1.86 | 80 | 149.4 | ±12.45 | 955 |
| sha512 | 512 | 293.2 | ±2.198 | 740 | 318.6 | ±1.851 | 50 | 153.4 | ±12.79 | 58 |
| sha512_224 | 224 | 256.2 | ±1.097 | 292 | 318.4 | ±1.736 | 55 | 154.8 | ±11.4 | 50 |
| sha512_256 | 256 | 256.3 | ±0.3129 | 561 | 317.5 | ±2.736 | 87 | 143.7 | ±11.89 | 355 |

### SHA-3 (FIPS 202)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| sha3_224 | 224 | 238 | ±13.84 | 625 | 307 | ±1.939 | 80 | 189.4 | ±15.7 | 177 |
| sha3_256 | 256 | 226.7 | ±7.664 | 80 | 286.8 | ±1.796 | 50 | 179.5 | ±14.84 | 50 |
| sha3_384 | 384 | 176.5 | ±7.119 | 478 | 223.1 | ±1.908 | 140 | 124.9 | ±10.4 | 2577 |
| sha3_512 | 512 | 134.5 | ±0.8357 | 920 | 156.9 | ±1.103 | 50 | 95.47 | ±6.359 | 5903 |

### SHAKE XOFs (FIPS 202; 32-byte squeeze)

| Hash | Out | Tolkien (M1) MB/s | Tolkien (M1) ±CI (90%) | Tolkien (M1) Runs | Dennard (EPYC 7452) MB/s | Dennard (EPYC 7452) ±CI (90%) | Dennard (EPYC 7452) Runs | Heinlein (Jetson) MB/s | Heinlein (Jetson) ±CI (90%) | Heinlein (Jetson) Runs |
|---|---|---|---|---|---|---|---|---|---|---|
| shake128 | xof | 262.4 | ±8.668 | 175 | 351.5 | ±1.199 | 50 | 209.8 | ±16.86 | 170 |
| shake256 | xof | 234.4 | ±1.655 | 770 | 286.6 | ±2.071 | 110 | 186.6 | ±14.84 | 53 |
