#!/usr/bin/env python3
"""Generic three-platform Kiviat (radar) chart generator.

Reads a CSV with columns:

    label,wigner,moore,darby

…and emits an SVG radar plot with three curves on a log-radial axis. Designed
for the 2026-05-08 wigner/moore/darby sweep, but stays generic enough that any
3-platform comparison set fits the same script.

Usage:

    python3 generate_three_platform_radar.py \
        --csv path/to/data.csv --out path/to/out.svg \
        --title "..." --units "MB/s" \
        [--min 1 --max 1024]

If `--min`/`--max` are omitted, log-radial bounds are auto-fit to the data
(rounded out to the nearest power of two).
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

# `radar_label_layout` lives in assets/ alongside the other radar helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "assets"))
from radar_label_layout import default_offset_y, spread_label_positions  # noqa: E402


WIGNER_COLOR = "#0f766e"  # teal — Apple Silicon (M1 Max)
MOORE_COLOR = "#1d4ed8"   # blue — AMD EPYC
DARBY_COLOR = "#b91c1c"   # red — RPi5 (ARM SBC)
BG_COLOR = "#fbf8f1"
GRID_COLOR = "#c9c2b7"
AXIS_COLOR = "#a79d90"
TEXT_COLOR = "#342f29"
SUBTEXT_COLOR = "#6b6257"

WIDTH = 720
HEIGHT = 760
CX = 360.0
CY = 295.0
RADIUS = 220.0


def polar(radius: float, angle: float) -> tuple[float, float]:
    return (CX + radius * math.cos(angle), CY + radius * math.sin(angle))


def fmt_points(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


def label_anchor(x: float) -> str:
    if x < CX - 20:
        return "end"
    if x > CX + 20:
        return "start"
    return "middle"


def auto_log2_bounds(values: list[float]) -> tuple[float, float]:
    finite = [v for v in values if v and v > 0 and math.isfinite(v)]
    if not finite:
        return (1.0, 1024.0)
    lo = min(finite)
    hi = max(finite)
    lo_pow = 2 ** math.floor(math.log2(lo))
    hi_pow = 2 ** math.ceil(math.log2(hi))
    if lo_pow == hi_pow:
        hi_pow *= 2
    return (lo_pow, hi_pow)


def value_radius(value: float, lo: float, hi: float) -> float:
    if value is None or not math.isfinite(value) or value <= 0:
        return 0.0
    clamped = min(max(value, lo), hi)
    span = math.log2(hi / lo)
    if span <= 0:
        return 0.0
    return RADIUS * math.log2(clamped / lo) / span


def scale_labels(lo: float, hi: float) -> list[float]:
    out = []
    v = lo
    while v <= hi + 1e-9:
        out.append(v)
        v *= 2
    return out


def parse_csv(path: Path) -> tuple[list[str], list[float], list[float], list[float]]:
    labels: list[str] = []
    a: list[float] = []
    b: list[float] = []
    c: list[float] = []
    with path.open(newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        if [h.strip().lower() for h in header[:4]] != ["label", "wigner", "moore", "darby"]:
            raise SystemExit(f"expected header label,wigner,moore,darby; got {header}")
        for row in reader:
            if not row or not row[0].strip():
                continue
            labels.append(row[0].strip())
            a.append(float(row[1]) if row[1].strip() else float("nan"))
            b.append(float(row[2]) if row[2].strip() else float("nan"))
            c.append(float(row[3]) if row[3].strip() else float("nan"))
    return labels, a, b, c


def generate_svg(args) -> str:
    labels, wigner_v, moore_v, darby_v = parse_csv(Path(args.csv))
    n = len(labels)
    if n < 3:
        raise SystemExit("need >=3 axes for a radar")

    if args.min is not None and args.max is not None:
        lo, hi = args.min, args.max
    else:
        lo, hi = auto_log2_bounds(wigner_v + moore_v + darby_v)

    angles = [(-math.pi / 2) + (2 * math.pi * i / n) for i in range(n)]
    rings = scale_labels(lo, hi)

    # Concentric rings.
    grid_polygons: list[str] = []
    for v in rings:
        r = value_radius(v, lo, hi)
        grid_polygons.append(fmt_points([polar(r, a) for a in angles]))

    spokes: list[tuple[float, float]] = [polar(RADIUS, a) for a in angles]

    # Curves.
    def curve(values: list[float]) -> list[tuple[float, float]]:
        return [polar(value_radius(v if v == v else lo, lo, hi), a) for v, a in zip(values, angles)]

    wigner_pts = curve(wigner_v)
    moore_pts = curve(moore_v)
    darby_pts = curve(darby_v)

    # Axis labels.
    label_entries: list[dict[str, float | str]] = []
    for label, ang in zip(labels, angles):
        x, y = polar(RADIUS + 22, ang)
        anchor = label_anchor(x)
        label_entries.append(
            {"label": label, "x": x, "y": default_offset_y(y, CY, RADIUS), "anchor": anchor}
        )
    spread_label_positions(label_entries, min_gap=14, min_y=CY - RADIUS - 30, max_y=CY + RADIUS + 60)

    # Build SVG.
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'width="{WIDTH}" height="{HEIGHT}" font-family="Inter, system-ui, sans-serif">'
    )
    parts.append(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="{BG_COLOR}"/>')

    if args.title:
        parts.append(
            f'<text x="{CX}" y="36" text-anchor="middle" font-size="20" '
            f'fill="{TEXT_COLOR}" font-weight="600">{args.title}</text>'
        )
    if args.units:
        parts.append(
            f'<text x="{CX}" y="58" text-anchor="middle" font-size="13" '
            f'fill="{SUBTEXT_COLOR}">log₂ radial axis ({args.units})</text>'
        )

    # Rings.
    for poly in grid_polygons:
        parts.append(
            f'<polygon points="{poly}" fill="none" stroke="{GRID_COLOR}" '
            f'stroke-width="0.7" stroke-dasharray="2,3"/>'
        )

    # Spokes.
    for sx, sy in spokes:
        parts.append(
            f'<line x1="{CX}" y1="{CY}" x2="{sx:.1f}" y2="{sy:.1f}" '
            f'stroke="{AXIS_COLOR}" stroke-width="0.6"/>'
        )

    # Ring scale labels (along the top spoke).
    top_angle = -math.pi / 2
    for v in rings:
        r = value_radius(v, lo, hi)
        x, y = polar(r, top_angle)
        parts.append(
            f'<text x="{x:.1f}" y="{y - 3:.1f}" font-size="9" '
            f'fill="{SUBTEXT_COLOR}" text-anchor="middle">{v:g}</text>'
        )

    # Curves: draw fills first, then outlines on top.
    for pts, color in (
        (wigner_pts, WIGNER_COLOR),
        (moore_pts, MOORE_COLOR),
        (darby_pts, DARBY_COLOR),
    ):
        poly = fmt_points(pts)
        parts.append(
            f'<polygon points="{poly}" fill="{color}" fill-opacity="0.10" '
            f'stroke="{color}" stroke-width="2.0" stroke-linejoin="round"/>'
        )
        for x, y in pts:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.0" fill="{color}"/>')

    # Axis labels.
    for entry in label_entries:
        parts.append(
            f'<text x="{float(entry["x"]):.1f}" y="{float(entry["y"]):.1f}" '
            f'font-size="12" fill="{TEXT_COLOR}" text-anchor="{entry["anchor"]}">'
            f'{entry["label"]}</text>'
        )

    # Legend.
    legend_y = HEIGHT - 60
    swatches = [
        ("Wigner (M1 Max, macOS)", WIGNER_COLOR),
        ("Moore (EPYC 7452, single-core)", MOORE_COLOR),
        ("Darby (RPi5, aarch64)", DARBY_COLOR),
    ]
    for i, (text, color) in enumerate(swatches):
        ly = legend_y + i * 18
        parts.append(
            f'<rect x="40" y="{ly - 10}" width="14" height="14" fill="{color}" '
            f'fill-opacity="0.30" stroke="{color}" stroke-width="1.5"/>'
        )
        parts.append(
            f'<text x="62" y="{ly + 1}" font-size="12" fill="{TEXT_COLOR}">{text}</text>'
        )

    parts.append("</svg>")
    return "".join(parts)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--title", default="")
    p.add_argument("--units", default="MB/s")
    p.add_argument("--min", type=float, default=None)
    p.add_argument("--max", type=float, default=None)
    args = p.parse_args()

    svg = generate_svg(args)
    Path(args.out).write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    main()
