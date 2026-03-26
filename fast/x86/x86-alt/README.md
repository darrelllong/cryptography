# x86 Alternative Kernels

Opt-in x86_64 acceleration kernels that are isolated from baseline `src/`.

Current kernels:

- AES-128 (AES-NI)
- AES-256 (AES-NI)
- GHASH multiply (PCLMULQDQ)

Usage:

```bash
bash fast/x86/scripts/run_alt_suite.sh
```
