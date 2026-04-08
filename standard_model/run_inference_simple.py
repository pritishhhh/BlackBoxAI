"""
Run standard-model inference against a CSV dataset.
"""
from __future__ import annotations

import hashlib
import os
import sys
import traceback

import numpy as np
import pandas as pd

pd.options.mode.chained_assignment = None
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, "reconfigure") else None
sys.stderr.reconfigure(line_buffering=True) if hasattr(sys.stderr, "reconfigure") else None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


def _stable_seed(value: object) -> int:
    digest = hashlib.sha256(str(value).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def _resolve_input_csv() -> str:
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])
    return os.path.join(PROJECT_ROOT, "datasets", "Standard", "standard_test_dataset.csv")


def _extract_file_id(row: pd.Series, default_idx: int) -> object:
    for column in ["fileId", "file_id", "id", "ID", "index"]:
        if column in row.index and pd.notna(row[column]):
            return row[column]
    return default_idx


def generate_binary(row: pd.Series, default_idx: int = 0) -> bytes:
    code_size = 1000
    for column in ["codeSize", "code_size", "size", "fileSize", "file_size", "length"]:
        if column in row.index and pd.notna(row[column]):
            try:
                code_size = max(16, int(float(row[column])))
                break
            except (TypeError, ValueError):
                continue

    rng = np.random.default_rng(_stable_seed(_extract_file_id(row, default_idx)))
    binary = bytearray()
    xor_count = min(int(code_size * 0.1), max(10, code_size // 3))

    for _ in range(xor_count):
        binary.append(0x31 + int(rng.integers(0, 5)))
        binary.append(int(rng.integers(0, 256)))

    while len(binary) < code_size:
        binary.append(int(rng.integers(0, 256)))

    return bytes(binary[:code_size])


def main() -> int:
    input_csv = _resolve_input_csv()
    output_csv = input_csv.replace(".csv", "_results.csv")
    checkpoint_path = os.path.join(SCRIPT_DIR, "checkpoints", "standard_model.pt")

    print("=" * 80)
    print("STANDARD MODEL - CSV INFERENCE")
    print("=" * 80)
    print()
    print("[1/5] Checking files...")
    print(f"  Script directory: {SCRIPT_DIR}")
    print(f"  Project root: {PROJECT_ROOT}")
    print(f"  Input CSV: {input_csv}")
    print(f"  Output CSV: {output_csv}")
    print()

    if not os.path.exists(input_csv):
        print(f"ERROR: Input CSV not found: {input_csv}")
        return 1

    if not os.path.exists(checkpoint_path):
        print(f"ERROR: Checkpoint not found: {checkpoint_path}")
        return 1

    print("OK: all required files found")
    print()
    print(f"[2/5] Loading CSV: {input_csv}")

    try:
        df = pd.read_csv(input_csv)
        print(f"OK: loaded {len(df)} samples and {len(df.columns)} columns")
    except Exception as exc:
        print(f"ERROR loading CSV: {exc}")
        return 1

    print()
    print("[3/5] Loading model...")
    print(f"  Checkpoint: {checkpoint_path}")

    try:
        from inference import CryptoDetector

        detector = CryptoDetector(checkpoint_path=checkpoint_path)
        print("OK: model loaded")
    except Exception as exc:
        print(f"ERROR loading model: {exc}")
        traceback.print_exc()
        return 1

    print()
    print(f"[4/5] Processing {len(df)} samples...")
    results = []

    for idx, row in df.iterrows():
        if (idx + 1) % 50 == 0:
            print(f"  Processed {idx + 1}/{len(df)}...")

        try:
            binary = generate_binary(row, default_idx=idx)
            if len(binary) < 16:
                print(f"  Warning: sample {idx} binary too small, skipping")
                continue

            detection_results = detector.detect(binary_data=binary)
            file_id = _extract_file_id(row, idx)
            result = {"fileId": file_id}
            detected = []

            for label, detection in detection_results["detections"].items():
                result[f"{label}_confidence"] = detection["confidence"]
                if detection["present"]:
                    detected.append(label)

            sorted_probs = sorted(
                detection_results["probabilities"].items(),
                key=lambda item: item[1],
                reverse=True,
            )
            result["top_predictions"] = ",".join(
                label for label, probability in sorted_probs[:3] if probability > 0.1
            ) or "none"
            result["detected_algorithms"] = ",".join(detected) or "none"

            for key, value in detection_results["signature_features"].items():
                result[key.lower()] = int(bool(value))

            results.append(result)
        except Exception as exc:
            print(f"  Error on sample {idx}: {str(exc)[:150]}")
            if idx < 3:
                traceback.print_exc()

    print()
    print(f"OK: processed {len(results)} samples")
    print()
    print(f"[5/5] Saving results to {output_csv}")

    try:
        results_df = pd.DataFrame(results)
        results_df.to_csv(output_csv, index=False)
        print("OK: results saved")
    except Exception as exc:
        print(f"ERROR saving results: {exc}")
        traceback.print_exc()
        return 1

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total samples processed: {len(results_df)}")
    print(f"Output: {output_csv}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
