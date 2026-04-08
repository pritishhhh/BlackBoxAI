# Proprietary Model

This model targets custom or non-standard cryptographic behavior in firmware-oriented samples.

## Scope

- Classification of proprietary algorithm families such as `CustomXOR`, `RotaryHash`, and `KeyScheduler`
- Signature scanning for S-boxes, permutations, rounds, and key-schedule patterns
- Transformer-based sequence modeling
- Fusion of learned features with structured metadata and entropy signals

## Files

- `config.py`: hyperparameters and dataset paths
- `generate_binaries.py`: synthetic dataset generation
- `train.py`: model training entry point
- `inference.py`: runtime inference pipeline
- `run_inference_simple.py`: CSV-based local sample runner
- `data/proprietary_dataset.py`: dataset assembly
- `models/`: proprietary model components
- `utils/`: tokenization, entropy, and feature extraction helpers

## Training

```powershell
cd proprietary_model
pip install -r requirements.txt
python train.py
```

Expected training dataset:

```text
datasets/Proprietary/proprietary_crypto_dataset.csv
```

Best checkpoints are written to:

```text
proprietary_model/checkpoints/proprietary_model.pt
```

## Sample Inference

From the repository root:

```powershell
cd proprietary_model
python run_inference_simple.py
```

Default input:

```text
datasets/Proprietary/proprietary_data_test.csv
```

Default output:

```text
datasets/Proprietary/proprietary_data_test_results.csv
```

## Notes

- The simple runner converts CSV rows into deterministic synthetic binary-like inputs so repeated runs stay stable.
- The Flask API uses the same model pipeline when serving proprietary inference requests.
