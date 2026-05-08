#!/usr/bin/env python3
"""Merge three Pilot markdown tables into side-by-side platform tables.

Modes:
- sym  : 3-column key (cipher, block, key); 3 metric columns (MB/s, ±CI, Runs)
- hash : 2-column key (hash, out);          3 metric columns (MB/s, ±CI, Runs)
- pk   : 1-column key (operation);          3 metric columns (ms/op, ±CI, Runs)

Each input file is the raw stdout of bench_all{,_hash,_pk_full}.sh.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
from pathlib import Path
from typing import Iterable


def parse_sections(path: Path) -> OrderedDict[str, list[list[str]]]:
    """Return {section_title: [row_cells, ...]} preserving order."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out: OrderedDict[str, list[list[str]]] = OrderedDict()
    section: str | None = None
    in_table = False

    for line in lines:
        if line.startswith("### "):
            section = line[4:].strip()
            out.setdefault(section, [])
            in_table = False
            continue

        if line.startswith("|") and (
            "| Cipher" in line or "| Operation" in line or "| Hash" in line
        ):
            in_table = True
            continue

        if in_table and line.startswith("|---"):
            continue

        if in_table and line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if section is None:
                section = "Ungrouped"
                out.setdefault(section, [])
            out[section].append(cells)
            continue

        if in_table and not line.strip():
            in_table = False

    return out


KEY_LEN = {"sym": 3, "hash": 2, "pk": 1}


def row_key(cells: list[str], mode: str) -> tuple[str, ...]:
    return tuple(cells[: KEY_LEN[mode]])


def fmt(v: str | None) -> str:
    return v if v is not None else "n/a"


def merge_rows(
    rows_a: list[list[str]],
    rows_b: list[list[str]],
    rows_c: list[list[str]],
    mode: str,
) -> list[tuple[tuple[str, ...], list[str] | None, list[str] | None, list[str] | None]]:
    a_map = {row_key(r, mode): r for r in rows_a}
    b_map = {row_key(r, mode): r for r in rows_b}
    c_map = {row_key(r, mode): r for r in rows_c}
    keys = list(a_map.keys())
    for key in b_map:
        if key not in a_map:
            keys.append(key)
    for key in c_map:
        if key not in a_map and key not in b_map:
            keys.append(key)
    return [
        (key, a_map.get(key), b_map.get(key), c_map.get(key))
        for key in keys
    ]


def metric_cells(row: list[str] | None, key_len: int) -> tuple[str, str, str]:
    if row is None:
        return ("n/a", "n/a", "n/a")
    base = row[key_len:]
    while len(base) < 3:
        base = base + ["n/a"]
    return (base[0], base[1], base[2])


def emit_table(
    sections: Iterable[
        tuple[
            str,
            list[
                tuple[
                    tuple[str, ...],
                    list[str] | None,
                    list[str] | None,
                    list[str] | None,
                ]
            ],
        ]
    ],
    labels: tuple[str, str, str],
    mode: str,
    confidence_pct: int,
) -> str:
    a_label, b_label, c_label = labels
    out: list[str] = []

    if mode == "sym":
        key_cols = ["Cipher", "Block", "Key"]
        unit = "MB/s"
    elif mode == "hash":
        key_cols = ["Hash", "Out"]
        unit = "MB/s"
    else:
        key_cols = ["Operation"]
        unit = "ms/op"

    for section, rows in sections:
        out.append(f"### {section}")
        out.append("")
        ci_lbl = f"±CI ({confidence_pct}%)"
        head = (
            "| "
            + " | ".join(key_cols)
            + " | "
            + " | ".join(
                f"{lbl} {col}"
                for lbl in (a_label, b_label, c_label)
                for col in (unit, ci_lbl, "Runs")
            )
            + " |"
        )
        out.append(head)
        sep = "|" + "|".join(["---"] * (len(key_cols) + 9)) + "|"
        out.append(sep)
        key_len = KEY_LEN[mode]
        for key, ra, rb, rc in rows:
            am, ac, ar = metric_cells(ra, key_len)
            bm, bc, br = metric_cells(rb, key_len)
            cm, cc, cr = metric_cells(rc, key_len)
            cells = list(key) + [am, ac, ar, bm, bc, br, cm, cc, cr]
            out.append("| " + " | ".join(cells) + " |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--a", required=True, type=Path, help="first platform raw bench output")
    parser.add_argument("--b", required=True, type=Path)
    parser.add_argument("--c", required=True, type=Path)
    parser.add_argument("--a-label", required=True)
    parser.add_argument("--b-label", required=True)
    parser.add_argument("--c-label", required=True)
    parser.add_argument("--mode", choices=["sym", "hash", "pk"], required=True)
    parser.add_argument(
        "--confidence-pct",
        type=int,
        default=90,
        help="confidence percent for the column header (default: 90)",
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    a = parse_sections(args.a)
    b = parse_sections(args.b)
    c = parse_sections(args.c)

    section_names: list[str] = list(a.keys())
    for src in (b, c):
        for name in src.keys():
            if name not in section_names:
                section_names.append(name)

    merged: list[
        tuple[
            str,
            list[
                tuple[
                    tuple[str, ...],
                    list[str] | None,
                    list[str] | None,
                    list[str] | None,
                ]
            ],
        ]
    ] = []
    for name in section_names:
        merged.append(
            (
                name,
                merge_rows(a.get(name, []), b.get(name, []), c.get(name, []), args.mode),
            )
        )

    text = emit_table(
        merged,
        (args.a_label, args.b_label, args.c_label),
        args.mode,
        args.confidence_pct,
    )
    args.out.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
