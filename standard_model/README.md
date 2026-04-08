# Standard Model

This model targets known cryptographic primitives in firmware-oriented samples.

## Scope

- Multi-label detection for common algorithms such as AES, RSA, HMAC, SHA, MD5, and ChaCha20
- Signature scanning for fixed constants and entropy hotspots
- Transformer-based opcode sequence modeling
- Fusion of signature, sequence, entropy, and metadata features

## Files

- `config.py`: training and inference configuration
- `train.py`: model training entry point
- `inference.py`: runtime inference pipeline
- `run_inference_simple.py`: CSV-based local sample runner
- `data/dataset_loader.py`: dataset assembly
- `models/`: model components
- `utils/`: tokenization, entropy, and metadata helpers

## Training

```powershell
cd standard_model
pip install -r requirements.txt
python train.py
```

Expected training dataset:

```text
datasets/Standard/crypto_30k.csv
```

Best checkpoints are written to:

```text
standard_model/checkpoints/standard_model.pt
```

## Sample Inference

From the repository root:

```powershell
cd standard_model
python run_inference_simple.py
```

Default input:

```text
datasets/Standard/standard_test_dataset.csv
```

Default output:

```text
datasets/Standard/standard_test_dataset_results.csv
```

## Notes

- The simple runner converts CSV rows into deterministic synthetic binary-like inputs so the local workflow remains reproducible.
- The API server uses the same inference pipeline for local CSV uploads.
