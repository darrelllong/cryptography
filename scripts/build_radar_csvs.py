#!/usr/bin/env python3
"""Extract per-platform metric CSVs from the 3-platform merged tables.

Reads the merged side-by-side tables produced by merge_three_pilot_tables.py
and emits CSVs in the form:

    label,wigner,moore,darby
    AES-128,356.4,235.7,139.8
    ...

…for the row sets we want on the Kiviat charts. Output CSVs feed
generate_three_platform_radar.py.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Iterable


SWEEP_DIR = Path(__file__).resolve().parent.parent / "bench" / "sweep-2026-05-08"
MERGED = SWEEP_DIR / "merged"
CSV_DIR = SWEEP_DIR / "csv"
CSV_DIR.mkdir(parents=True, exist_ok=True)


def parse_merged(path: Path) -> dict[str, dict[str, float]]:
    """Return {row_key: {platform: value}} where row_key is the first cell text.

    Each metric column triplet (mean, ±CI, Runs) is collapsed to the mean only.
    Platform labels are inferred from the heading row.
    """
    text = path.read_text(encoding="utf-8")
    rows: dict[str, dict[str, float]] = {}
    sections = re.split(r"^### ", text, flags=re.MULTILINE)
    for section in sections[1:]:
        # Keep blank lines so the index logic below stays explicit.
        lines = section.splitlines()
        # lines[0]: section title; some blank lines; then table header,
        # separator, rows. Find the first line that starts with "|".
        try:
            header_idx = next(i for i, ln in enumerate(lines) if ln.startswith("|"))
        except StopIteration:
            continue
        if len(lines) < header_idx + 3:
            continue
        header = [h.strip() for h in lines[header_idx].strip().strip("|").split("|")]
        # Identify columns named "<platform> MB/s" or "<platform> ms/op".
        platform_cols: list[tuple[str, int]] = []
        for idx, name in enumerate(header):
            m = re.match(r"^(.*?)(?:\s+)(MB/s|ms/op)$", name)
            if m:
                platform = m.group(1).strip()
                platform_cols.append((platform, idx))
        # Locate the key column count: header columns minus 3 metric columns
        # per platform.
        key_count = len(header) - 3 * len(platform_cols)
        if key_count <= 0:
            continue
        for row in lines[header_idx + 2 :]:
            if not row.startswith("|"):
                continue
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            row_key = cells[0]
            entry = rows.setdefault(row_key, {})
            for platform, idx in platform_cols:
                value_str = cells[idx]
                try:
                    entry[platform] = float(value_str)
                except (ValueError, TypeError):
                    entry[platform] = float("nan")
    return rows


def write_csv(name: str, rows: list[tuple[str, dict[str, float]]], platforms: list[str]) -> Path:
    path = CSV_DIR / f"{name}.csv"
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        # Hardcode the column order matching the radar generator's expectation.
        w.writerow(["label"] + ["wigner", "moore", "darby"])
        for label, vals in rows:
            v_w = vals.get(platforms[0], float("nan"))
            v_m = vals.get(platforms[1], float("nan"))
            v_d = vals.get(platforms[2], float("nan"))
            w.writerow(
                [
                    label,
                    "" if v_w != v_w else f"{v_w:g}",
                    "" if v_m != v_m else f"{v_m:g}",
                    "" if v_d != v_d else f"{v_d:g}",
                ]
            )
    return path


# Curated representative axis sets for each radar.
SYM_REPRESENTATIVE = [
    ("AES-128", "aes128"),
    ("AES-256", "aes256"),
    ("Camellia-128", "camellia128"),
    ("CAST-128", "cast128"),
    ("DES", "des"),
    ("Grasshopper", "grasshopper"),
    ("Magma", "magma"),
    ("PRESENT-80", "present80"),
    ("SEED", "seed"),
    ("Serpent-128", "serpent128"),
    ("SM4", "sm4"),
    ("Twofish-128", "twofish128"),
    ("ChaCha20", "chacha20"),
    ("Salsa20", "salsa20"),
    ("Rabbit", "rabbit"),
    ("SNOW 3G", "snow3g"),
    ("ZUC-128", "zuc128"),
]

HASH_REPRESENTATIVE = [
    ("MD5", "md5"),
    ("SHA-1", "sha1"),
    ("RIPEMD-160", "ripemd160"),
    ("SHA-256", "sha256"),
    ("SHA-512", "sha512"),
    ("SHA3-256", "sha3_256"),
    ("SHA3-512", "sha3_512"),
    ("SHAKE128", "shake128"),
    ("SHAKE256", "shake256"),
]

PK_RSA_DSA_EC = [
    ("RSA-2048 sign", "rsa_sign_2048"),
    ("RSA-2048 verify", "rsa_verify_2048"),
    ("RSA-1024 keygen", "rsa_keygen_1024"),
    ("ECDSA sign", "ecdsa_sign"),
    ("ECDSA verify", "ecdsa_verify"),
    ("ECDH agree", "ecdh_agree"),
    ("Ed25519 sign", "ed25519_sign"),
    ("Ed25519 verify", "ed25519_verify"),
    ("X25519 agree", "x25519_agree"),
    ("X448 agree", "x448_agree"),
    ("DSA-1024 sign", "dsa_sign_1024"),
    ("DSA-1024 verify", "dsa_verify_1024"),
]

PK_PQ = [
    ("ML-KEM-512 keygen", "mlkem512_keygen"),
    ("ML-KEM-512 encaps", "mlkem512_encaps"),
    ("ML-KEM-512 decaps", "mlkem512_decaps"),
    ("ML-KEM-768 encaps", "mlkem768_encaps"),
    ("ML-KEM-1024 encaps", "mlkem1024_encaps"),
    ("ML-DSA-44 sign", "mldsa44_sign"),
    ("ML-DSA-44 verify", "mldsa44_verify"),
    ("ML-DSA-65 sign", "mldsa65_sign"),
    ("ML-DSA-87 sign", "mldsa87_sign"),
    ("NTRU-HRSS-701 encaps", "ntruhrss701_encaps"),
    ("NTRU-HPS-509 encaps", "ntruhps509_encaps"),
    ("NTRU-EES-401EP1 enc", "ntruees401ep1_encrypt"),
]


def select(rows: dict[str, dict[str, float]], pairs: Iterable[tuple[str, str]]) -> list[tuple[str, dict[str, float]]]:
    out: list[tuple[str, dict[str, float]]] = []
    for label, key in pairs:
        if key in rows:
            out.append((label, rows[key]))
        else:
            print(f"  warning: missing row {key} in source")
    return out


def main() -> None:
    sym = parse_merged(MERGED / "symmetric.md")
    hsh = parse_merged(MERGED / "hash.md")
    pk = parse_merged(MERGED / "pk.md")

    # Platform labels from the merged tables look like "Wigner (M1 Max)" etc.
    # The CSV writer collapses to short tokens for the radar generator.
    PLATFORMS = ["Wigner (M1 Max)", "Moore (EPYC 7452)", "Darby (RPi5)"]

    print("Symmetric rows:", len(sym))
    print("Hash rows:", len(hsh))
    print("PK rows:", len(pk))

    # PK is in ms/op; for ops/sec radar invert to (1000 / ms_per_op).
    def invert_to_ops_per_sec(rows: list[tuple[str, dict[str, float]]]) -> list[tuple[str, dict[str, float]]]:
        out = []
        for label, vals in rows:
            inv = {}
            for k, v in vals.items():
                inv[k] = (1000.0 / v) if v == v and v > 0 else float("nan")
            out.append((label, inv))
        return out

    write_csv("symmetric", select(sym, SYM_REPRESENTATIVE), PLATFORMS)
    write_csv("hash", select(hsh, HASH_REPRESENTATIVE), PLATFORMS)
    write_csv("pk_rsa_ec", invert_to_ops_per_sec(select(pk, PK_RSA_DSA_EC)), PLATFORMS)
    write_csv("pk_pq", invert_to_ops_per_sec(select(pk, PK_PQ)), PLATFORMS)

    print("CSVs written to", CSV_DIR)


if __name__ == "__main__":
    main()
