# BlackBoxAI API

The local API is a Flask service that exposes both model pipelines for CSV-based inference.

## Quick Start

### Install dependencies

```powershell
pip install -r requirements_api.txt
```

### Start the server

```powershell
python api_server.py
```

Default address: `http://localhost:5000`

## Endpoints

### `GET /api/health`

Returns backend health and model load state.

```json
{
  "status": "ok",
  "proprietary_loaded": true,
  "standard_loaded": true
}
```

### `POST /api/standard/inference`

- Input: multipart form upload with a `file` field containing a CSV file
- Output: downloadable CSV containing standard-model predictions

### `POST /api/proprietary/inference`

- Input: multipart form upload with a `file` field containing a CSV file
- Output: downloadable CSV containing proprietary-model predictions

## Frontend Integration

The UI integration lives in:

- `frontend/src/lib/api.ts`
- `frontend/src/components/ModelInference.tsx`
- `frontend/src/pages/ApiIntegration.tsx`

The frontend expects this environment variable:

```dotenv
VITE_API_URL=http://localhost:5000
```

See [frontend/.env.example](../frontend/.env.example).

## CSV Expectations

The server accepts general CSV files and derives a few optional fields when present:

- `fileId`, `file_id`, `id`, or `ID`
- `codeSize`, `code_size`, `size`, or `fileSize`

Missing values fall back to deterministic defaults so sample inference can still run.

## Security Notes

- The current local API does not implement authentication or rate limiting.
- The repository does not ship production API keys.
- If you expose this server publicly, add authentication, request validation, and deployment hardening first.
