#!/bin/bash
# Cortex-X925 column of the cryptography sweep, Pilot f01eec4, pinned to CPU 9.
set -u
S=$HOME/rerun/sweep-2026-09-28
cd $S/work
export PILOT_BENCH_CLI=$HOME/pilot-bench/build/cli/bench
export PILOT_CIPHER_BIN=$HOME/rerun/cryptography/target/release/pilot_cipher
export PILOT_HASH_BIN=$HOME/rerun/cryptography/target/release/pilot_hash
export PILOT_PK_BIN=$HOME/rerun/cryptography/target/release/pilot_pk
export PILOT_PRESET=normal PILOT_CONFIDENCE_LEVEL=0.90 PILOT_SESSION_LIMIT=300
R=$HOME/rerun/cryptography/scripts
date -Is > $S/start.txt; uptime >> $S/start.txt
/usr/bin/time -f "%e s" -o $S/symmetric.time taskset -c 9 bash $R/bench_all.sh      > $S/symmetric.md 2> $S/symmetric.stderr
/usr/bin/time -f "%e s" -o $S/hash.time      taskset -c 9 bash $R/bench_all_hash.sh > $S/hash.md      2> $S/hash.stderr
uptime > $S/mid.txt
/usr/bin/time -f "%e s" -o $S/pk.time        taskset -c 9 bash $R/bench_all_pk_full.sh > $S/pk.md    2> $S/pk.stderr
date -Is > $S/end.txt; uptime >> $S/end.txt
touch $S/done
