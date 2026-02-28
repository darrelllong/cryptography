#!/usr/bin/env python3
"""Train a DNN distinguisher over raw 32-byte cipher outputs.

This script intentionally trains only on the fast cipher implementations.
The `*Ct` variants are excluded because, for a correct implementation, they
produce exactly the same bits as the fast path for the same key and input.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import warnings
from pathlib import Path
from typing import Any

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
warnings.filterwarnings(
    "ignore",
    message=r"urllib3 v2 only supports OpenSSL 1\.1\.1\+",
    category=Warning,
)

import numpy as np
import tensorflow as tf


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = REPO_ROOT / "ml" / "data"
DEFAULT_OUT_DIR = REPO_ROOT / "ml" / "out"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a TensorFlow classifier on raw 32-byte cipher outputs."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--train-per-class", type=int, default=20_000)
    parser.add_argument("--val-per-class", type=int, default=4_000)
    parser.add_argument("--test-per-class", type=int, default=4_000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
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
    return samples.reshape(rows, sample_len).astype(np.int32), labels.astype(np.int32)


def residual_block(
    x: tf.Tensor, filters: int, kernel_size: int, dilation_rate: int, dropout: float
) -> tf.Tensor:
    residual = x
    x = tf.keras.layers.Conv1D(
        filters, kernel_size, padding="same", dilation_rate=dilation_rate
    )(x)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Activation("gelu")(x)
    x = tf.keras.layers.SpatialDropout1D(dropout)(x)
    x = tf.keras.layers.Conv1D(filters, 1, padding="same")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    if residual.shape[-1] != filters:
        residual = tf.keras.layers.Conv1D(filters, 1, padding="same")(residual)
    x = tf.keras.layers.Add()([x, residual])
    return tf.keras.layers.Activation("gelu")(x)


def build_model(sample_len: int, class_count: int, learning_rate: float) -> tf.keras.Model:
    inputs = tf.keras.Input(shape=(sample_len,), dtype="int32", name="bytes")
    x = tf.keras.layers.Embedding(input_dim=256, output_dim=32, name="byte_embedding")(inputs)
    x = tf.keras.layers.Conv1D(128, 5, padding="same")(x)
    x = tf.keras.layers.BatchNormalization()(x)
    x = tf.keras.layers.Activation("gelu")(x)

    x = residual_block(x, 128, 5, 1, 0.05)
    x = residual_block(x, 128, 3, 2, 0.05)
    x = residual_block(x, 192, 3, 4, 0.08)
    x = residual_block(x, 192, 3, 1, 0.08)
    x = residual_block(x, 256, 3, 2, 0.10)
    x = residual_block(x, 256, 3, 4, 0.10)

    avg_pool = tf.keras.layers.GlobalAveragePooling1D()(x)
    max_pool = tf.keras.layers.GlobalMaxPooling1D()(x)
    x = tf.keras.layers.Concatenate()([avg_pool, max_pool])
    x = tf.keras.layers.Dense(512, activation="gelu")(x)
    x = tf.keras.layers.Dropout(0.25)(x)
    x = tf.keras.layers.Dense(256, activation="gelu")(x)
    x = tf.keras.layers.Dropout(0.20)(x)
    outputs = tf.keras.layers.Dense(class_count, activation="softmax", name="class_id")(x)

    model = tf.keras.Model(inputs=inputs, outputs=outputs, name="cipher_distinguisher")
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss=tf.keras.losses.SparseCategoricalCrossentropy(),
        metrics=[
            tf.keras.metrics.SparseCategoricalAccuracy(name="accuracy"),
            tf.keras.metrics.SparseTopKCategoricalAccuracy(k=3, name="top3"),
        ],
    )
    return model


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> None:
    args = parse_args()
    tf.keras.utils.set_random_seed(args.seed)

    maybe_generate_dataset(args)
    manifest = load_manifest(args.data_dir)
    sample_len = int(manifest["sample_len"])
    class_names = list(manifest["classes"])

    x_train, y_train = load_split(args.data_dir, "train", sample_len)
    x_val, y_val = load_split(args.data_dir, "val", sample_len)
    x_test, y_test = load_split(args.data_dir, "test", sample_len)

    model = build_model(sample_len, len(class_names), args.learning_rate)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    best_model_path = args.output_dir / "cipher_distinguisher.keras"
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_accuracy", patience=8, restore_best_weights=True
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=3, min_lr=1e-5
        ),
        tf.keras.callbacks.ModelCheckpoint(
            filepath=str(best_model_path),
            monitor="val_accuracy",
            mode="max",
            save_best_only=True,
        ),
        tf.keras.callbacks.CSVLogger(str(args.output_dir / "history.csv")),
    ]

    history = model.fit(
        x_train,
        y_train,
        validation_data=(x_val, y_val),
        epochs=args.epochs,
        batch_size=args.batch_size,
        shuffle=True,
        callbacks=callbacks,
        verbose=2,
    )

    metric_map = {
        key: float(value)
        for key, value in model.evaluate(
            x_test, y_test, batch_size=args.batch_size, verbose=0, return_dict=True
        ).items()
    }

    predictions = model.predict(x_test, batch_size=args.batch_size, verbose=0)
    predicted = np.argmax(predictions, axis=1)
    confusion = tf.math.confusion_matrix(
        y_test, predicted, num_classes=len(class_names)
    ).numpy()

    model.save(best_model_path)
    model.save_weights(args.output_dir / "cipher_distinguisher.weights.h5")

    save_json(args.output_dir / "labels.json", {"classes": class_names})
    save_json(
        args.output_dir / "metrics.json",
        {
            "seed": args.seed,
            "sample_len": sample_len,
            "classes": class_names,
            "train_samples": int(x_train.shape[0]),
            "val_samples": int(x_val.shape[0]),
            "test_samples": int(x_test.shape[0]),
            "test_metrics": metric_map,
            "confusion_matrix": confusion.tolist(),
            "best_val_accuracy": float(max(history.history["val_accuracy"])),
        },
    )

    print(f"saved model to {best_model_path}")
    print(f"saved weights to {args.output_dir / 'cipher_distinguisher.weights.h5'}")
    for name, value in metric_map.items():
        print(f"test_{name}: {value:.6f}")


if __name__ == "__main__":
    main()
