# Frontend

This directory contains the React/Vite dashboard for BlackBoxAI.

## Commands

```powershell
npm install
npm run dev
npm run build
```

## Environment

Create `frontend/.env` from `frontend/.env.example` and set:

```dotenv
VITE_API_URL=http://localhost:5000
```

The upload and API integration pages are wired to the local Flask server in the repository root.
