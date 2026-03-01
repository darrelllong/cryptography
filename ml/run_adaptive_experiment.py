#!/usr/bin/env python3
"""Run an adaptive overnight sequence of PyTorch distinguisher experiments."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_ROOT = REPO_ROOT / "ml" / "out" / "adaptive"


@dataclass(frozen=True)
class Stage:
    name: str
    sample_len: int
    model_size: str
    train_per_class: int
    val_per_class: int
    test_per_class: int
    epochs: int
    batch_size: int


DEFAULT_STAGES = (
    Stage("s32_base", 32, "base", 20_000, 4_000, 4_000, 20, 512),
    Stage("s256_large", 256, "large", 20_000, 4_000, 4_000, 16, 256),
    Stage("s1024_large", 1024, "large", 8_000, 2_000, 2_000, 12, 128),
    Stage("s1024_xlarge", 1024, "xlarge", 8_000, 2_000, 2_000, 10, 96),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a staged experiment plan that widens samples or increases model "
            "capacity when earlier runs stay near chance."
        )
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--chance-margin",
        type=float,
        default=0.01,
        help="How far above chance a test accuracy must be before we try to confirm it.",
    )
    parser.add_argument(
        "--confirm-runs",
        type=int,
        default=2,
        help="How many additional seeds to rerun on the same stage when a candidate signal appears.",
    )
    parser.add_argument(
        "--device",
        choices=("auto", "mps", "cpu"),
        default="auto",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned commands without executing them.",
    )
    return parser.parse_args()


def load_metrics(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def stage_command(stage: Stage, seed: int, output_dir: Path, device: str) -> list[str]:
    return [
        sys.executable,
        "ml/train_distinguisher.py",
        "--generate",
        "--sample-len",
        str(stage.sample_len),
        "--train-per-class",
        str(stage.train_per_class),
        "--val-per-class",
        str(stage.val_per_class),
        "--test-per-class",
        str(stage.test_per_class),
        "--epochs",
        str(stage.epochs),
        "--batch-size",
        str(stage.batch_size),
        "--model-size",
        stage.model_size,
        "--seed",
        str(seed),
        "--device",
        device,
        "--output-dir",
        str(output_dir),
    ]


def run_stage(stage: Stage, seed: int, output_dir: Path, device: str, dry_run: bool) -> dict[str, Any]:
    cmd = stage_command(stage, seed, output_dir, device)
    print(f"\n==> {stage.name} seed={seed}")
    print(" ".join(cmd))
    if dry_run:
        return {
            "stage": stage.name,
            "seed": seed,
            "output_dir": str(output_dir),
            "dry_run": True,
        }

    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    metrics = load_metrics(output_dir / "metrics.json")
    chance = 1.0 / len(metrics["classes"])
    test_accuracy = float(metrics["test_metrics"]["accuracy"])
    print(
        f"stage={stage.name} seed={seed} "
        f"test_accuracy={test_accuracy:.6f} chance={chance:.6f}",
        flush=True,
    )
    return {
        "stage": stage.name,
        "seed": seed,
        "output_dir": str(output_dir),
        "test_accuracy": test_accuracy,
        "chance": chance,
        "best_val_accuracy": float(metrics["best_val_accuracy"]),
        "sample_len": int(metrics["sample_len"]),
        "model_size": str(metrics["model_size"]),
    }


def main() -> None:
    args = parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "seed_base": args.seed,
        "chance_margin": args.chance_margin,
        "confirm_runs": args.confirm_runs,
        "device": args.device,
        "runs": [],
        "decision": None,
    }

    for stage_index, stage in enumerate(DEFAULT_STAGES):
        seed = args.seed + stage_index * 1000
        output_dir = args.output_root / f"{stage.name}-seed{seed}"
        result = run_stage(stage, seed, output_dir, args.device, args.dry_run)
        summary["runs"].append(result)

        if args.dry_run:
            continue

        threshold = result["chance"] + args.chance_margin
        if result["test_accuracy"] <= threshold:
            print(
                f"{stage.name}: no signal above threshold "
                f"({result['test_accuracy']:.6f} <= {threshold:.6f}), escalating.",
                flush=True,
            )
            continue

        confirmations = []
        for confirm_index in range(args.confirm_runs):
            confirm_seed = seed + confirm_index + 1
            confirm_dir = args.output_root / f"{stage.name}-seed{confirm_seed}"
            confirm_result = run_stage(
                stage, confirm_seed, confirm_dir, args.device, args.dry_run
            )
            summary["runs"].append(confirm_result)
            confirmations.append(confirm_result)

        avg_accuracy = (
            result["test_accuracy"]
            + sum(run["test_accuracy"] for run in confirmations)
        ) / (1 + len(confirmations))

        if avg_accuracy > threshold:
            summary["decision"] = {
                "type": "candidate_signal",
                "stage": stage.name,
                "average_test_accuracy": avg_accuracy,
                "threshold": threshold,
            }
            write_json(args.output_root / "adaptive_summary.json", summary)
            print(
                f"{stage.name}: repeated runs stayed above threshold; "
                f"stopping for manual inspection.",
                flush=True,
            )
            return

        print(
            f"{stage.name}: initial spike did not survive confirmation "
            f"(avg {avg_accuracy:.6f} <= {threshold:.6f}); escalating.",
            flush=True,
        )

    if summary["decision"] is None:
        summary["decision"] = {"type": "no_signal_found"}
    write_json(args.output_root / "adaptive_summary.json", summary)
    print("finished adaptive schedule with no confirmed signal.", flush=True)


if __name__ == "__main__":
    main()
