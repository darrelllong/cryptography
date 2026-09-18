#!/usr/bin/env python3
"""Merge Pilot markdown tables into one side-by-side platform table.

Modes:
- sym  : 3-column key (cipher, block, key); 3 metric columns (MB/s, ±CI, Runs)
- hash : 2-column key (hash, out);          3 metric columns (MB/s, ±CI, Runs)
- pk   : 1-column key (operation);          3 metric columns (ms/op, ±CI, Runs)

Each input file is the raw stdout of bench_all{,_hash,_pk_full}.sh. Any
number of platforms may be given, each as ``--input LABEL=PATH``; the column
order follows the order of those flags, and a row missing from one platform
reads "n/a" there rather than dropping out of the table.
"""

from __future__ import annotations

import argparse
import re
from collections import OrderedDict
from pathlib import Path
from typing import Iterable


# The confidence percent printed in an input table header, e.g. "±CI (95%)".
CI_HEADER = re.compile(r"±CI \((\d+)%\)")
# Pseudo-section under which parse_sections records the percents it saw.
CI_KEY = "__ci_percent__"


def confidence_percent(tables: list, requested: int | None) -> int:
    """The one confidence percent every input header carries.

    Headers that disagree with each other, or with ``--confidence-pct`` when
    it is given, are an error: the merged header must not relabel intervals
    it did not compute.
    """
    seen = {pct for t in tables for pct in t.get(CI_KEY, [])}
    if requested is not None:
        seen.add(str(requested))
    if len(seen) != 1:
        raise SystemExit(f"confidence percents disagree across inputs and flags: {sorted(seen)}")
    return int(seen.pop())


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
            ci = CI_HEADER.search(line)
            if ci is not None:
                out.setdefault(CI_KEY, []).append(ci.group(1))
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
    per_platform: list[list[list[str]]],
    mode: str,
) -> list[tuple[tuple[str, ...], list[list[str] | None]]]:
    """Rows keyed across platforms, in the order the first platform lists them.

    A key the first platform does not have is appended when a later one
    introduces it, so a platform that measured something the others did not
    still appears.
    """
    maps = [{row_key(r, mode): r for r in rows} for rows in per_platform]
    keys: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()
    for table in maps:
        for key in table:
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return [(key, [table.get(key) for table in maps]) for key in keys]


def metric_cells(row: list[str] | None, key_len: int) -> tuple[str, str, str]:
    if row is None:
        return ("n/a", "n/a", "n/a")
    base = row[key_len:]
    while len(base) < 3:
        base = base + ["n/a"]
    return (base[0], base[1], base[2])


def emit_table(
    sections: Iterable[tuple[str, list[tuple[tuple[str, ...], list[list[str] | None]]]]],
    labels: list[str],
    mode: str,
    confidence_pct: int,
) -> str:
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

    # Three metric columns per platform: the reading, its interval, and the
    # rounds pilot-bench needed to reach it.
    metrics_per_platform = 3

    for section, rows in sections:
        out.append(f"### {section}")
        out.append("")
        ci_lbl = f"±CI ({confidence_pct}%)"
        head = (
            "| "
            + " | ".join(key_cols)
            + " | "
            + " | ".join(
                f"{lbl} {col}" for lbl in labels for col in (unit, ci_lbl, "Runs")
            )
            + " |"
        )
        out.append(head)
        columns = len(key_cols) + metrics_per_platform * len(labels)
        out.append("|" + "|".join(["---"] * columns) + "|")
        key_len = KEY_LEN[mode]
        for key, per_platform in rows:
            cells = list(key)
            for row in per_platform:
                cells.extend(metric_cells(row, key_len))
            out.append("| " + " | ".join(cells) + " |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def platform(spec: str) -> tuple[str, Path]:
    """Parse ``LABEL=PATH``. The label heads the platform's columns."""
    label, separator, path = spec.partition("=")
    if not separator or not label or not path:
        raise argparse.ArgumentTypeError(f"expected LABEL=PATH, got {spec!r}")
    return label, Path(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=platform,
        metavar="LABEL=PATH",
        help="a platform's raw bench output and the label its columns carry; "
        "repeat once per platform, in the column order wanted",
    )
    parser.add_argument("--mode", choices=["sym", "hash", "pk"], required=True)
    parser.add_argument(
        "--confidence-pct",
        type=int,
        default=None,
        help="confidence percent the inputs must carry in their headers "
        "(default: read from the inputs, which must agree)",
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    labels = [label for label, _ in args.input]
    if len(set(labels)) != len(labels):
        raise SystemExit(f"platform labels repeat: {labels}")
    tables = [parse_sections(path) for _, path in args.input]
    confidence_pct = confidence_percent(tables, args.confidence_pct)
    for table in tables:
        table.pop(CI_KEY, None)

    section_names: list[str] = []
    for table in tables:
        for name in table:
            if name not in section_names:
                section_names.append(name)

    merged = [
        (name, merge_rows([table.get(name, []) for table in tables], args.mode))
        for name in section_names
    ]

    args.out.write_text(
        emit_table(merged, labels, args.mode, confidence_pct), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
