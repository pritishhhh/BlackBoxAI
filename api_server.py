"""
Local Flask API for BlackBoxAI model inference.
"""
from __future__ import annotations

import hashlib
import io
import os
from typing import Any

import numpy as np
import pandas as pd
from flask import Flask, request, send_file
from flask_cors import CORS

from proprietary_model.inference import ProprietaryInference
from standard_model.inference import CryptoDetector

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
HOST = os.getenv("MODEL_API_HOST", "0.0.0.0")
PORT = int(os.getenv("MODEL_API_PORT", os.getenv("PORT", "5000")))
CORS_ORIGINS = os.getenv("MODEL_API_CORS_ORIGINS", "*")

app = Flask(__name__)
if CORS_ORIGINS == "*":
    CORS(app, resources={r"/api/*": {"origins": "*"}})
else:
    allowed_origins = [origin.strip() for origin in CORS_ORIGINS.split(",") if origin.strip()]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

proprietary_engine: ProprietaryInference | None = None
standard_engine: CryptoDetector | None = None


def _stable_seed(value: Any) -> int:
    digest = hashlib.sha256(str(value).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big")


def _extract_file_id(row: pd.Series, default_idx: int) -> Any:
    for column in ["fileId", "file_id", "id", "ID"]:
        if column in row.index and pd.notna(row[column]):
            return row[column]
    return default_idx


def init_proprietary_engine() -> ProprietaryInference:
    global proprietary_engine
    if proprietary_engine is None:
        checkpoint_path = os.path.join(
            PROJECT_ROOT,
            "proprietary_model",
            "checkpoints",
            "proprietary_model.pt",
        )
        print("Loading proprietary model...")
        proprietary_engine = ProprietaryInference(checkpoint_path=checkpoint_path)
        print("Proprietary model ready.")
    return proprietary_engine


def init_standard_engine() -> CryptoDetector:
    global standard_engine
    if standard_engine is None:
        checkpoint_path = os.path.join(
            PROJECT_ROOT,
            "standard_model",
            "checkpoints",
            "standard_model.pt",
        )
        print("Loading standard model...")
        standard_engine = CryptoDetector(checkpoint_path=checkpoint_path)
        print("Standard model ready.")
    return standard_engine


def generate_binary_from_row(row: pd.Series, default_idx: int = 0) -> bytes:
    code_size = 1000
    for column in ["codeSize", "code_size", "size", "fileSize"]:
        if column in row.index and pd.notna(row[column]):
            try:
                code_size = max(100, int(float(row[column])))
                break
            except (TypeError, ValueError):
                continue

    sample_id = _extract_file_id(row, default_idx)
    rng = np.random.default_rng(_stable_seed(sample_id))
    return rng.integers(0, 256, size=code_size, dtype=np.uint8).tobytes()


def _results_to_csv_download(results: list[dict[str, Any]], filename: str):
    results_df = pd.DataFrame(results)
    output = io.StringIO()
    results_df.to_csv(output, index=False)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/health", methods=["GET"])
def health():
    return {
        "status": "ok",
        "proprietary_loaded": proprietary_engine is not None,
        "standard_loaded": standard_engine is not None,
    }


@app.route("/api/proprietary/inference", methods=["POST"])
def proprietary_inference():
    try:
        if "file" not in request.files:
            return {"error": "No file provided"}, 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return {"error": "No file selected"}, 400

        df = pd.read_csv(uploaded_file)
        engine = init_proprietary_engine()
        print(f"Processing {len(df)} samples with proprietary model...")

        results: list[dict[str, Any]] = []
        for idx, row in df.iterrows():
            try:
                binary = generate_binary_from_row(row, idx)
                result = engine.analyze_binary(binary)
                result["fileId"] = _extract_file_id(row, idx)
                results.append(result)
            except Exception as exc:  # pragma: no cover - best-effort batch execution
                print(f"Skipping proprietary row {idx}: {str(exc)[:120]}")

        return _results_to_csv_download(results, "proprietary_results.csv")
    except Exception as exc:
        return {"error": str(exc)}, 500


@app.route("/api/standard/inference", methods=["POST"])
def standard_inference():
    try:
        if "file" not in request.files:
            return {"error": "No file provided"}, 400

        uploaded_file = request.files["file"]
        if uploaded_file.filename == "":
            return {"error": "No file selected"}, 400

        df = pd.read_csv(uploaded_file)
        engine = init_standard_engine()
        print(f"Processing {len(df)} samples with standard model...")

        results: list[dict[str, Any]] = []
        for idx, row in df.iterrows():
            try:
                binary = generate_binary_from_row(row, idx)
                result = engine.detect(binary_data=binary)

                formatted_result: dict[str, Any] = {
                    "fileId": _extract_file_id(row, idx),
                }

                detected_algorithms = []
                for label, detection in result["detections"].items():
                    formatted_result[f"{label}_confidence"] = detection["confidence"]
                    if detection["present"]:
                        detected_algorithms.append(label)

                sorted_probabilities = sorted(
                    result["probabilities"].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
                formatted_result["top_predictions"] = ",".join(
                    label for label, probability in sorted_probabilities[:3] if probability > 0.1
                ) or "none"
                formatted_result["detected_algorithms"] = ",".join(detected_algorithms) or "none"

                for key, value in result["signature_features"].items():
                    formatted_result[key.lower()] = int(bool(value))

                results.append(formatted_result)
            except Exception as exc:  # pragma: no cover - best-effort batch execution
                print(f"Skipping standard row {idx}: {str(exc)[:120]}")

        return _results_to_csv_download(results, "standard_results.csv")
    except Exception as exc:
        return {"error": str(exc)}, 500


if __name__ == "__main__":
    print("=" * 70)
    print("BlackBoxAI Model API Server")
    print("=" * 70)
    print()
    print("Endpoints:")
    print("  GET  /api/health")
    print("  POST /api/standard/inference")
    print("  POST /api/proprietary/inference")
    print()
    print(f"Starting server on http://localhost:{PORT}")
    print()

    app.run(host=HOST, port=PORT, debug=False)
