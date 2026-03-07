#!/usr/bin/env python3
"""Merge two Pilot markdown tables into side-by-side platform tables."""

from __future__ import annotations

import argparse
from collections import OrderedDict
from pathlib import Path
from typing import Iterable


def parse_sections(path: Path) -> OrderedDict[str, list[list[str]]]:
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

        if line.startswith("|") and ("| Cipher" in line or "| Operation" in line):
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


def row_key(cells: list[str], mode: str) -> tuple[str, ...]:
    if mode == "sym":
        return (cells[0], cells[1], cells[2])
    return (cells[0],)


def fmt(v: str | None) -> str:
    return v if v is not None else "n/a"


def merge_rows(
    lhs_rows: list[list[str]],
    rhs_rows: list[list[str]],
    mode: str,
) -> list[tuple[list[str], list[str] | None, list[str] | None]]:
    lhs_map = {row_key(r, mode): r for r in lhs_rows}
    rhs_map = {row_key(r, mode): r for r in rhs_rows}
    keys = list(lhs_map.keys())
    for key in rhs_map:
        if key not in lhs_map:
            keys.append(key)
    return [(list(key), lhs_map.get(key), rhs_map.get(key)) for key in keys]


def emit_sym(
    sections: Iterable[tuple[str, list[tuple[list[str], list[str] | None, list[str] | None]]]],
    lhs_label: str,
    rhs_label: str,
) -> str:
    out: list[str] = []
    for section, rows in sections:
        out.append(f"### {section}")
        out.append("")
        out.append(
            f"| Cipher | Block | Key | {lhs_label} MB/s | {lhs_label} ±CI | {lhs_label} Runs | "
            f"{rhs_label} MB/s | {rhs_label} ±CI | {rhs_label} Runs |"
        )
        out.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        for key, lhs, rhs in rows:
            out.append(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                    key[0],
                    key[1],
                    key[2],
                    fmt(lhs[3] if lhs else None),
                    fmt(lhs[4] if lhs else None),
                    fmt(lhs[5] if lhs else None),
                    fmt(rhs[3] if rhs else None),
                    fmt(rhs[4] if rhs else None),
                    fmt(rhs[5] if rhs else None),
                )
            )
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def emit_pk(
    sections: Iterable[tuple[str, list[tuple[list[str], list[str] | None, list[str] | None]]]],
    lhs_label: str,
    rhs_label: str,
) -> str:
    out: list[str] = []
    for section, rows in sections:
        out.append(f"### {section}")
        out.append("")
        out.append(
            f"| Operation | {lhs_label} ms/op | {lhs_label} ±CI | {lhs_label} Runs | "
            f"{rhs_label} ms/op | {rhs_label} ±CI | {rhs_label} Runs |"
        )
        out.append("|---|---:|---:|---:|---:|---:|---:|")
        for key, lhs, rhs in rows:
            out.append(
                "| {} | {} | {} | {} | {} | {} | {} |".format(
                    key[0],
                    fmt(lhs[1] if lhs else None),
                    fmt(lhs[2] if lhs else None),
                    fmt(lhs[3] if lhs else None),
                    fmt(rhs[1] if rhs else None),
                    fmt(rhs[2] if rhs else None),
                    fmt(rhs[3] if rhs else None),
                )
            )
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--right", required=True, type=Path)
    parser.add_argument("--left-label", required=True)
    parser.add_argument("--right-label", required=True)
    parser.add_argument("--mode", choices=["sym", "pk"], required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    left = parse_sections(args.left)
    right = parse_sections(args.right)

    section_names: list[str] = list(left.keys())
    for name in right.keys():
        if name not in left:
            section_names.append(name)

    merged: list[tuple[str, list[tuple[list[str], list[str] | None, list[str] | None]]]] = []
    for name in section_names:
        merged.append(
            (
                name,
                merge_rows(left.get(name, []), right.get(name, []), args.mode),
            )
        )

    if args.mode == "sym":
        text = emit_sym(merged, args.left_label, args.right_label)
    else:
        text = emit_pk(merged, args.left_label, args.right_label)

    args.out.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
