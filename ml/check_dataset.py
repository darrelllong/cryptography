#!/usr/bin/env python3
"""Audit a generated ML dataset for obvious leakage and integrity problems."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


SPLITS = ("train", "val", "test")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check the raw 32-byte dataset for integrity and leakage red flags."
    )
    parser.add_argument("--data-dir", type=Path, default=Path("ml/data"))
    parser.add_argument(
        "--max-duplicate-examples",
        type=int,
        default=5,
        help="How many duplicate sample hex strings to print per split.",
    )
    return parser.parse_args()


def load_manifest(data_dir: Path) -> dict[str, Any]:
    with (data_dir / "manifest.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_split(data_dir: Path, split: str, sample_len: int) -> tuple[list[bytes], list[int]]:
    sample_bytes = (data_dir / f"{split}_samples.bin").read_bytes()
    label_bytes = (data_dir / f"{split}_labels.bin").read_bytes()

    if len(sample_bytes) % sample_len != 0:
        raise ValueError(
            f"{split}: sample file size {len(sample_bytes)} is not divisible by sample_len={sample_len}"
        )

    rows = len(sample_bytes) // sample_len
    if rows != len(label_bytes):
        raise ValueError(
            f"{split}: samples/labels mismatch ({rows} rows vs {len(label_bytes)} labels)"
        )

    samples = [
        sample_bytes[i * sample_len : (i + 1) * sample_len]
        for i in range(rows)
    ]
    labels = list(label_bytes)
    return samples, labels


def digest(sample: bytes) -> bytes:
    return hashlib.blake2b(sample, digest_size=16).digest()


def entropy_from_counts(counts: list[int], total: int) -> float:
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def position_entropy(samples: list[bytes], sample_len: int) -> tuple[float, float, float]:
    tables = [[0] * 256 for _ in range(sample_len)]
    for sample in samples:
        for idx, value in enumerate(sample):
            tables[idx][value] += 1

    entropies = [entropy_from_counts(table, len(samples)) for table in tables]
    return min(entropies), sum(entropies) / len(entropies), max(entropies)


def byte_summary(samples: list[bytes]) -> tuple[float, float]:
    total = sum(len(sample) for sample in samples)
    byte_sum = sum(value for sample in samples for value in sample)
    mean = byte_sum / total
    variance = sum((value - mean) ** 2 for sample in samples for value in sample) / total
    return mean, math.sqrt(variance)


def duplicate_report(
    samples: list[bytes], max_examples: int
) -> tuple[int, list[str], Counter[bytes]]:
    counts = Counter(samples)
    duplicates = [sample.hex() for sample, count in counts.items() if count > 1]
    duplicate_rows = sum(count - 1 for count in counts.values() if count > 1)
    return duplicate_rows, duplicates[:max_examples], counts


def class_balance(labels: list[int], class_count: int) -> list[int]:
    counts = [0] * class_count
    for label in labels:
        if 0 <= label < class_count:
            counts[label] += 1
    return counts


def print_split_report(
    split: str,
    samples: list[bytes],
    labels: list[int],
    class_names: list[str],
    expected_rows: int,
    max_duplicate_examples: int,
) -> tuple[set[bytes], Counter[bytes]]:
    print(f"[{split}]")
    print(f"rows: {len(samples)} (expected {expected_rows})")

    bad_labels = [label for label in labels if label < 0 or label >= len(class_names)]
    if bad_labels:
        raise ValueError(f"{split}: found {len(bad_labels)} out-of-range labels")

    balance = class_balance(labels, len(class_names))
    print("class balance:")
    for name, count in zip(class_names, balance):
        print(f"  {name:>12}: {count}")

    dup_rows, dup_examples, counts = duplicate_report(samples, max_duplicate_examples)
    print(f"duplicate rows within split: {dup_rows}")
    if dup_examples:
        print("duplicate examples:")
        for example in dup_examples:
            print(f"  {example}")

    mean, stddev = byte_summary(samples)
    min_h, mean_h, max_h = position_entropy(samples, len(samples[0]) if samples else 0)
    print(f"byte mean: {mean:.3f} (ideal ~127.5)")
    print(f"byte stddev: {stddev:.3f} (ideal ~73.9)")
    print(
        "position entropy: "
        f"min {min_h:.4f} / mean {mean_h:.4f} / max {max_h:.4f} bits (ideal ~8.0)"
    )
    print()

    return {digest(sample) for sample in samples}, counts


def main() -> None:
    args = parse_args()
    manifest = load_manifest(args.data_dir)

    sample_len = int(manifest["sample_len"])
    class_names = list(manifest["classes"])
    expected = {
        "train": int(manifest["train_samples"]),
        "val": int(manifest["val_samples"]),
        "test": int(manifest["test_samples"]),
    }

    print(f"dataset: {args.data_dir}")
    print(f"sample_len: {sample_len}")
    print(f"classes ({len(class_names)}): {', '.join(class_names)}")
    print(f"seed: {manifest['seed']}")
    print()

    split_digests: dict[str, set[bytes]] = {}
    split_counts: dict[str, Counter[bytes]] = {}

    for split in SPLITS:
        samples, labels = load_split(args.data_dir, split, sample_len)
        digests, counts = print_split_report(
            split,
            samples,
            labels,
            class_names,
            expected[split],
            args.max_duplicate_examples,
        )
        split_digests[split] = digests
        split_counts[split] = counts

    print("[cross-split overlap]")
    for left, right in (("train", "val"), ("train", "test"), ("val", "test")):
        overlap = split_digests[left] & split_digests[right]
        print(f"{left} vs {right}: {len(overlap)} overlapping rows")


if __name__ == "__main__":
    main()
