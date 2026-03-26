# x86 Optimization Workspace (No ASM, In-Repo Only)

This directory mirrors the Apple-Silicon optimization workflow for x86_64.

Constraints:

- No assembly language.
- No external crypto crates or copied implementations.
- Baseline `src/` behavior and API stay unchanged.

Policy:

- `src/` remains the canonical pure safe Rust baseline.
- x86 acceleration work is an explicit alternative path.
- Publish only kernels that clear the `>=5x` speedup gate.

## Current Alternative Kernels

Implemented in:

- `fast/x86/x86-alt/src/aes128_x86.rs`
- `fast/x86/x86-alt/src/aes256_x86.rs`
- `fast/x86/x86-alt/src/ghash_x86.rs`

Run parity + microbench:

```bash
bash fast/x86/scripts/compare_aes128_alt.sh 5000
bash fast/x86/scripts/compare_aes256_alt.sh 5000
bash fast/x86/scripts/compare_ghash_alt.sh 5000
bash fast/x86/scripts/run_alt_suite.sh
```

## Notes

- AES paths require CPU AES-NI support.
- GHASH path requires CPU PCLMULQDQ support.
- Scripts write markdown outputs into `fast/x86/results/`.
