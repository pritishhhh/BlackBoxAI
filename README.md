# BlackBoxAI

BlackBoxAI is a firmware cryptography analysis project built around two model pipelines:

- `standard_model/` detects known cryptographic primitives such as AES, RSA, SHA, HMAC, and related families.
- `proprietary_model/` classifies custom or non-standard cryptographic patterns from synthetic and feature-driven samples.
- `api_server.py` exposes both models through a local Flask API.
- `frontend/` provides a React/Vite dashboard for local demos and API integration.

## Repository Layout

```text
.
|- api_server.py
|- datasets/
|  |- Standard/
|  `- Proprietary/
|- docs/
|  |- api.md
|  `- local-inference.md
|- frontend/
|- proprietary_model/
`- standard_model/
```

## What Is Implemented

- Local inference for both model families.
- Sample datasets for standard and proprietary workflows.
- A frontend upload flow wired to the local API.
- A basic Flask service that accepts CSV input and returns CSV outputs.

## Current Scope

This repository is a local research/demo project, not a production SaaS service.

- The API currently accepts CSV inputs rather than deployed multi-tenant binary analysis jobs.
- Authentication, persistence, job queues, and production hardening are not implemented.
- Some dashboard pages are presentational and meant to illustrate product direction; the upload and API integration flows are the main connected paths.

## Quick Start

### 1. Install Python dependencies

```powershell
pip install -r requirements_api.txt
```

If you want to train models instead of only running inference, also install the model-specific requirements:

```powershell
pip install -r standard_model/requirements.txt
pip install -r proprietary_model/requirements.txt
```

### 2. Start the backend

```powershell
python api_server.py
```

The API defaults to `http://localhost:5000`.

### 3. Start the frontend

```powershell
cd frontend
npm install
npm run dev
```

Create `frontend/.env` from `frontend/.env.example` if you want to point the UI at a different backend URL.

### 4. Run sample inference from the command line

```powershell
.\run_sample_inference.bat
```

That helper runs both model pipelines against the sample datasets in `datasets/`.

## Datasets

- `datasets/Standard/crypto_30k.csv`
- `datasets/Standard/standard_test_dataset.csv`
- `datasets/Proprietary/proprietary_crypto_dataset.csv`
- `datasets/Proprietary/proprietary_data_test.csv`

Generated result files are intentionally ignored so the repo stays clean after local runs.

## Documentation

- API usage: [docs/api.md](docs/api.md)
- Local sample inference: [docs/local-inference.md](docs/local-inference.md)
- Frontend notes: [frontend/README.md](frontend/README.md)
- Standard model notes: [standard_model/README.md](standard_model/README.md)
- Proprietary model notes: [proprietary_model/README.md](proprietary_model/README.md)

## Publishing Notes

- No production API keys or secrets are committed in this repository.
- Local environments, caches, logs, and build artifacts are ignored.
- A license file is not included yet. Add one before publishing if you want explicit reuse terms.
