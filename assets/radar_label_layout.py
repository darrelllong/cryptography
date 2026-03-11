"""Shared label-layout helpers for SVG radar chart generators.

The helpers keep axis labels readable when multiple labels land at similar
vertical positions on the same side of the chart.
"""

from __future__ import annotations


def default_offset_y(base_y: float, center_y: float, radius: float) -> float:
    """Apply the standard radial label offset used by the chart generators."""
    if base_y < center_y - radius + 30:
        return base_y
    if base_y > center_y + radius - 30:
        return base_y + 12
    return base_y + 4


def spread_label_positions(
    entries: list[dict[str, float | str]],
    *,
    min_gap: float,
    min_y: float,
    max_y: float,
) -> None:
    """Spread labels vertically per text-anchor group to avoid collisions."""
    for anchor in ("end", "middle", "start"):
        group = [idx for idx, entry in enumerate(entries) if entry["anchor"] == anchor]
        if len(group) < 2:
            continue

        group.sort(key=lambda idx: float(entries[idx]["y"]))
        ys = [float(entries[idx]["y"]) for idx in group]

        for i in range(1, len(ys)):
            ys[i] = max(ys[i], ys[i - 1] + min_gap)

        overflow = ys[-1] - max_y
        if overflow > 0:
            ys = [y - overflow for y in ys]

        underflow = min_y - ys[0]
        if underflow > 0:
            ys = [y + underflow for y in ys]

        for i in range(len(ys) - 2, -1, -1):
            ys[i] = min(ys[i], ys[i + 1] - min_gap)

        underflow = min_y - ys[0]
        if underflow > 0:
            ys = [y + underflow for y in ys]

        overflow = ys[-1] - max_y
        if overflow > 0:
            ys = [y - overflow for y in ys]

        for idx, y in zip(group, ys):
            entries[idx]["y"] = y
