#!/usr/bin/env python3
"""Train PyTorch distinguisher models over raw N-byte cipher outputs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = REPO_ROOT / "ml" / "data"
DEFAULT_OUT_DIR = REPO_ROOT / "ml" / "out"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a PyTorch classifier on raw N-byte cipher outputs."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--train-per-class", type=int, default=20_000)
    parser.add_argument("--val-per-class", type=int, default=4_000)
    parser.add_argument("--test-per-class", type=int, default=4_000)
    parser.add_argument("--sample-len", type=int, default=32)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument(
        "--model-size",
        choices=("base", "large", "xlarge"),
        default="base",
        help="Capacity tier for the selected classifier architecture.",
    )
    parser.add_argument(
        "--architecture",
        choices=("cnn", "transformer", "byte_transformer"),
        default="cnn",
        help=(
            "Model family to train: cnn (residual 1D CNN), transformer "
            "(patch Transformer), or byte_transformer (byte-level attention)."
        ),
    )
    parser.add_argument(
        "--patch-len",
        type=int,
        default=16,
        help="Patch width in bytes for the patch-transformer encoder.",
    )
    parser.add_argument(
        "--device",
        choices=("auto", "mps", "cpu"),
        default="auto",
        help="Use MPS when available unless forced to CPU.",
    )
    return parser.parse_args()


def maybe_generate_dataset(args: argparse.Namespace) -> None:
    manifest = args.data_dir / "manifest.json"
    if manifest.exists() and not args.generate:
        return

    args.data_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "cargo",
        "run",
        "--release",
        "--bin",
        "gen_ml_dataset",
        "--",
        "--output",
        str(args.data_dir),
        "--sample-len",
        str(args.sample_len),
        "--train-per-class",
        str(args.train_per_class),
        "--val-per-class",
        str(args.val_per_class),
        "--test-per-class",
        str(args.test_per_class),
        "--seed",
        str(args.seed),
    ]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)


def load_manifest(data_dir: Path) -> dict[str, Any]:
    with (data_dir / "manifest.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_split(data_dir: Path, split: str, sample_len: int) -> tuple[np.ndarray, np.ndarray]:
    samples = np.fromfile(data_dir / f"{split}_samples.bin", dtype=np.uint8)
    labels = np.fromfile(data_dir / f"{split}_labels.bin", dtype=np.uint8)
    if samples.size % sample_len != 0:
        raise ValueError(f"{split} samples file is not divisible by sample_len={sample_len}")
    rows = samples.size // sample_len
    if rows != labels.size:
        raise ValueError(
            f"{split} samples/labels mismatch: {rows} rows vs {labels.size} labels"
        )
    return samples.reshape(rows, sample_len), labels.astype(np.int64)


def choose_device(requested: str) -> torch.device:
    if requested == "cpu":
        return torch.device("cpu")
    mps_ok = torch.backends.mps.is_built() and torch.backends.mps.is_available()
    if requested == "mps":
        if not mps_ok:
            raise RuntimeError("MPS requested but not available in this Python process")
        return torch.device("mps")
    return torch.device("mps" if mps_ok else "cpu")


def set_seed(seed: int) -> None:
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.backends.mps.is_available():
        torch.mps.manual_seed(seed)


class ResidualBlock(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, kernel_size: int, dropout: float):
        super().__init__()
        padding = kernel_size // 2
        self.conv1 = nn.Conv1d(in_channels, out_channels, kernel_size, padding=padding)
        self.bn1 = nn.BatchNorm1d(out_channels)
        self.conv2 = nn.Conv1d(out_channels, out_channels, 1)
        self.bn2 = nn.BatchNorm1d(out_channels)
        self.dropout = nn.Dropout(dropout)
        self.skip = (
            nn.Identity()
            if in_channels == out_channels
            else nn.Conv1d(in_channels, out_channels, 1)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = self.skip(x)
        x = self.conv1(x)
        x = self.bn1(x)
        x = torch.nn.functional.gelu(x)
        x = self.dropout(x)
        x = self.conv2(x)
        x = self.bn2(x)
        x = x + residual
        return torch.nn.functional.gelu(x)


@dataclass(frozen=True)
class ModelSpec:
    embedding_dim: int
    channels: tuple[int, ...]
    head_dims: tuple[int, ...]
    dropouts: tuple[float, ...]


@dataclass(frozen=True)
class TransformerSpec:
    embedding_dim: int
    model_dim: int
    ff_dim: int
    layers: int
    heads: int
    dropout: float
    head_dim: int


MODEL_SPECS = {
    "base": ModelSpec(
        embedding_dim=32,
        channels=(128, 128, 192, 192, 256, 256),
        head_dims=(512, 256),
        dropouts=(0.05, 0.05, 0.08, 0.08, 0.10, 0.10),
    ),
    "large": ModelSpec(
        embedding_dim=64,
        channels=(192, 192, 256, 256, 384, 384, 384, 384),
        head_dims=(1024, 512),
        dropouts=(0.05, 0.05, 0.08, 0.08, 0.10, 0.10, 0.12, 0.12),
    ),
    "xlarge": ModelSpec(
        embedding_dim=96,
        channels=(256, 256, 384, 384, 512, 512, 512, 512, 512, 512),
        head_dims=(1536, 768),
        dropouts=(0.05, 0.05, 0.08, 0.08, 0.10, 0.10, 0.12, 0.12, 0.12, 0.12),
    ),
}


TRANSFORMER_SPECS = {
    "base": TransformerSpec(
        embedding_dim=32,
        model_dim=192,
        ff_dim=768,
        layers=4,
        heads=6,
        dropout=0.10,
        head_dim=256,
    ),
    "large": TransformerSpec(
        embedding_dim=48,
        model_dim=256,
        ff_dim=1024,
        layers=6,
        heads=8,
        dropout=0.10,
        head_dim=384,
    ),
    "xlarge": TransformerSpec(
        embedding_dim=64,
        model_dim=384,
        ff_dim=1536,
        layers=8,
        heads=12,
        dropout=0.12,
        head_dim=512,
    ),
}


class CipherNet(nn.Module):
    def __init__(self, class_count: int, spec: ModelSpec):
        super().__init__()
        self.embedding = nn.Embedding(256, spec.embedding_dim)
        first_channels = spec.channels[0]
        self.stem = nn.Sequential(
            nn.Conv1d(spec.embedding_dim, first_channels, kernel_size=5, padding=2),
            nn.BatchNorm1d(first_channels),
            nn.GELU(),
        )
        blocks: list[nn.Module] = []
        in_channels = first_channels
        for idx, out_channels in enumerate(spec.channels):
            kernel_size = 5 if idx == 0 else 3
            blocks.append(
                ResidualBlock(in_channels, out_channels, kernel_size, spec.dropouts[idx])
            )
            in_channels = out_channels
        self.blocks = nn.Sequential(*blocks)
        pooled = in_channels * 2

        head_layers: list[nn.Module] = []
        head_in = pooled
        for idx, head_dim in enumerate(spec.head_dims):
            head_layers.extend(
                [
                    nn.Linear(head_in, head_dim),
                    nn.GELU(),
                    nn.Dropout(0.25 if idx == 0 else 0.20),
                ]
            )
            head_in = head_dim
        head_layers.append(nn.Linear(head_in, class_count))
        self.head = nn.Sequential(*head_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x)  # [B, L, C]
        x = x.transpose(1, 2)  # [B, C, L]
        x = self.stem(x)
        x = self.blocks(x)
        avg_pool = x.mean(dim=2)
        max_pool = x.amax(dim=2)
        x = torch.cat([avg_pool, max_pool], dim=1)
        return self.head(x)


class CipherPatchTransformer(nn.Module):
    def __init__(self, sample_len: int, class_count: int, spec: TransformerSpec, patch_len: int):
        super().__init__()
        if patch_len <= 0:
            raise ValueError("patch_len must be greater than zero")
        self.patch_len = patch_len
        self.embedding = nn.Embedding(256, spec.embedding_dim)
        self.patch_proj = nn.Conv1d(
            spec.embedding_dim,
            spec.model_dim,
            kernel_size=patch_len,
            stride=patch_len,
        )
        token_count = math.ceil(sample_len / patch_len) + 1  # +1 for CLS
        self.cls_token = nn.Parameter(torch.zeros(1, 1, spec.model_dim))
        self.positional = nn.Parameter(torch.zeros(1, token_count, spec.model_dim))
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=spec.model_dim,
            nhead=spec.heads,
            dim_feedforward=spec.ff_dim,
            dropout=spec.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=False,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=spec.layers)
        self.norm = nn.LayerNorm(spec.model_dim)
        self.head = nn.Sequential(
            nn.Linear(spec.model_dim, spec.head_dim),
            nn.GELU(),
            nn.Dropout(spec.dropout),
            nn.Linear(spec.head_dim, class_count),
        )

        nn.init.normal_(self.cls_token, std=0.02)
        nn.init.normal_(self.positional, std=0.02)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x)  # [B, L, C]
        x = x.transpose(1, 2)  # [B, C, L]
        remainder = x.size(2) % self.patch_len
        if remainder:
            pad = self.patch_len - remainder
            x = torch.nn.functional.pad(x, (0, pad))
        x = self.patch_proj(x)  # [B, D, T]
        x = x.transpose(1, 2)  # [B, T, D]
        cls = self.cls_token.expand(x.size(0), -1, -1)
        x = torch.cat([cls, x], dim=1)
        x = x + self.positional[:, : x.size(1), :]
        x = self.encoder(x)
        x = self.norm(x[:, 0, :])
        return self.head(x)


class CipherByteTransformer(nn.Module):
    def __init__(self, sample_len: int, class_count: int, spec: TransformerSpec):
        super().__init__()
        token_count = sample_len + 1  # +1 for CLS
        self.embedding = nn.Embedding(256, spec.embedding_dim)
        self.input_proj = nn.Linear(spec.embedding_dim, spec.model_dim)
        self.cls_token = nn.Parameter(torch.zeros(1, 1, spec.model_dim))
        self.positional = nn.Parameter(torch.zeros(1, token_count, spec.model_dim))
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=spec.model_dim,
            nhead=spec.heads,
            dim_feedforward=spec.ff_dim,
            dropout=spec.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=False,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=spec.layers)
        self.norm = nn.LayerNorm(spec.model_dim)
        self.head = nn.Sequential(
            nn.Linear(spec.model_dim, spec.head_dim),
            nn.GELU(),
            nn.Dropout(spec.dropout),
            nn.Linear(spec.head_dim, class_count),
        )

        nn.init.normal_(self.cls_token, std=0.02)
        nn.init.normal_(self.positional, std=0.02)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x)  # [B, L, C]
        x = self.input_proj(x)  # [B, L, D]
        cls = self.cls_token.expand(x.size(0), -1, -1)
        x = torch.cat([cls, x], dim=1)
        x = x + self.positional[:, : x.size(1), :]
        x = self.encoder(x)
        x = self.norm(x[:, 0, :])
        return self.head(x)


@dataclass
class EpochStats:
    loss: float
    accuracy: float
    top3: float


def make_loader(samples: np.ndarray, labels: np.ndarray, batch_size: int, shuffle: bool) -> DataLoader:
    xs = torch.from_numpy(samples.astype(np.int64, copy=False))
    ys = torch.from_numpy(labels.astype(np.int64, copy=False))
    return DataLoader(
        TensorDataset(xs, ys),
        batch_size=batch_size,
        shuffle=shuffle,
        drop_last=False,
    )


def evaluate(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
    criterion: nn.Module,
) -> tuple[EpochStats, np.ndarray, np.ndarray]:
    model.eval()
    total_loss = 0.0
    total = 0
    correct = 0
    top3 = 0
    all_labels: list[torch.Tensor] = []
    all_preds: list[torch.Tensor] = []

    with torch.no_grad():
        for x, y in loader:
            x = x.to(device, non_blocking=False)
            y = y.to(device, non_blocking=False)
            logits = model(x)
            loss = criterion(logits, y)
            batch = y.size(0)
            total_loss += loss.item() * batch
            total += batch
            pred = logits.argmax(dim=1)
            correct += (pred == y).sum().item()
            topk = logits.topk(k=min(3, logits.size(1)), dim=1).indices
            top3 += (topk == y.unsqueeze(1)).any(dim=1).sum().item()
            all_labels.append(y.detach().cpu())
            all_preds.append(pred.detach().cpu())

    stats = EpochStats(
        loss=total_loss / total,
        accuracy=correct / total,
        top3=top3 / total,
    )
    labels = torch.cat(all_labels).numpy()
    preds = torch.cat(all_preds).numpy()
    return stats, labels, preds


def train_epoch(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
    criterion: nn.Module,
    optimizer: torch.optim.Optimizer,
) -> EpochStats:
    model.train()
    total_loss = 0.0
    total = 0
    correct = 0
    top3 = 0

    for x, y in loader:
        x = x.to(device, non_blocking=False)
        y = y.to(device, non_blocking=False)

        optimizer.zero_grad(set_to_none=True)
        logits = model(x)
        loss = criterion(logits, y)
        loss.backward()
        optimizer.step()

        batch = y.size(0)
        total_loss += loss.item() * batch
        total += batch
        pred = logits.argmax(dim=1)
        correct += (pred == y).sum().item()
        topk = logits.topk(k=min(3, logits.size(1)), dim=1).indices
        top3 += (topk == y.unsqueeze(1)).any(dim=1).sum().item()

    return EpochStats(
        loss=total_loss / total,
        accuracy=correct / total,
        top3=top3 / total,
    )


def confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, class_count: int) -> list[list[int]]:
    matrix = np.zeros((class_count, class_count), dtype=np.int64)
    for truth, pred in zip(y_true, y_pred):
        matrix[truth, pred] += 1
    return matrix.tolist()


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_history(path: Path, rows: list[dict[str, float]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "epoch",
                "learning_rate",
                "train_loss",
                "train_accuracy",
                "train_top3",
                "val_loss",
                "val_accuracy",
                "val_top3",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def build_model(
    sample_len: int,
    class_count: int,
    architecture: str,
    model_size: str,
    patch_len: int,
) -> nn.Module:
    if architecture == "cnn":
        return CipherNet(class_count, MODEL_SPECS[model_size])
    if architecture == "transformer":
        return CipherPatchTransformer(
            sample_len, class_count, TRANSFORMER_SPECS[model_size], patch_len
        )
    return CipherByteTransformer(sample_len, class_count, TRANSFORMER_SPECS[model_size])


def main() -> None:
    args = parse_args()
    set_seed(args.seed)
    maybe_generate_dataset(args)

    manifest = load_manifest(args.data_dir)
    sample_len = int(manifest["sample_len"])
    class_names = list(manifest["classes"])

    train_x, train_y = load_split(args.data_dir, "train", sample_len)
    val_x, val_y = load_split(args.data_dir, "val", sample_len)
    test_x, test_y = load_split(args.data_dir, "test", sample_len)

    device = choose_device(args.device)
    print(f"using device: {device}", flush=True)

    train_loader = make_loader(train_x, train_y, args.batch_size, shuffle=True)
    val_loader = make_loader(val_x, val_y, args.batch_size, shuffle=False)
    test_loader = make_loader(test_x, test_y, args.batch_size, shuffle=False)

    model = build_model(
        sample_len,
        len(class_names),
        args.architecture,
        args.model_size,
        args.patch_len,
    ).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3, min_lr=1e-5
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    best_model_path = args.output_dir / "cipher_distinguisher.pt"
    best_state_dict_path = args.output_dir / "cipher_distinguisher_state_dict.pt"

    best_val_acc = -1.0
    best_val_loss = math.inf
    best_epoch = 0
    history_rows: list[dict[str, float]] = []
    patience = 8
    stale_epochs = 0

    for epoch in range(1, args.epochs + 1):
        train_stats = train_epoch(model, train_loader, device, criterion, optimizer)
        val_stats, _, _ = evaluate(model, val_loader, device, criterion)
        scheduler.step(val_stats.loss)

        row = {
            "epoch": epoch,
            "learning_rate": optimizer.param_groups[0]["lr"],
            "train_loss": train_stats.loss,
            "train_accuracy": train_stats.accuracy,
            "train_top3": train_stats.top3,
            "val_loss": val_stats.loss,
            "val_accuracy": val_stats.accuracy,
            "val_top3": val_stats.top3,
        }
        history_rows.append(row)
        print(
            f"epoch {epoch:02d}: "
            f"train_acc={train_stats.accuracy:.4f} val_acc={val_stats.accuracy:.4f} "
            f"train_loss={train_stats.loss:.4f} val_loss={val_stats.loss:.4f} "
            f"lr={optimizer.param_groups[0]['lr']:.6f}",
            flush=True,
        )

        improved = (val_stats.accuracy > best_val_acc) or (
            val_stats.accuracy == best_val_acc and val_stats.loss < best_val_loss
        )
        if improved:
            best_val_acc = val_stats.accuracy
            best_val_loss = val_stats.loss
            best_epoch = epoch
            stale_epochs = 0
            checkpoint = {
                "model_state_dict": model.state_dict(),
                "sample_len": sample_len,
                "classes": class_names,
                "architecture": args.architecture,
                "patch_len": args.patch_len,
                "best_epoch": best_epoch,
                "best_val_accuracy": best_val_acc,
                "best_val_loss": best_val_loss,
            }
            torch.save(checkpoint, best_model_path)
            torch.save(model.state_dict(), best_state_dict_path)
        else:
            stale_epochs += 1
            if stale_epochs >= patience:
                break

    checkpoint = torch.load(best_model_path, map_location=device)
    model.load_state_dict(checkpoint["model_state_dict"])
    test_stats, y_true, y_pred = evaluate(model, test_loader, device, criterion)

    write_history(args.output_dir / "history.csv", history_rows)
    save_json(args.output_dir / "labels.json", {"classes": class_names})
    save_json(
        args.output_dir / "metrics.json",
        {
            "seed": args.seed,
            "device": str(device),
            "architecture": args.architecture,
            "model_size": args.model_size,
            "patch_len": args.patch_len,
            "sample_len": sample_len,
            "classes": class_names,
            "train_samples": int(train_x.shape[0]),
            "val_samples": int(val_x.shape[0]),
            "test_samples": int(test_x.shape[0]),
            "best_epoch": best_epoch,
            "best_val_accuracy": best_val_acc,
            "test_metrics": {
                "loss": test_stats.loss,
                "accuracy": test_stats.accuracy,
                "top3": test_stats.top3,
            },
            "confusion_matrix": confusion_matrix(y_true, y_pred, len(class_names)),
        },
    )

    print(f"saved model to {best_model_path}", flush=True)
    print(f"saved weights to {best_state_dict_path}", flush=True)
    print(f"test_accuracy: {test_stats.accuracy:.6f}", flush=True)
    print(f"test_loss: {test_stats.loss:.6f}", flush=True)
    print(f"test_top3: {test_stats.top3:.6f}", flush=True)


if __name__ == "__main__":
    main()
