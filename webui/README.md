# TriageKit React UI (Vite)

Modern control surface for the **same** TriageKit detection engines (no heuristics removed or weakened).

## Develop

```bash
pip install -e .
triagekit serve

cd webui
npm install
npm run dev
```

Open http://127.0.0.1:5173 (proxies `/api` → FastAPI :8000).

## Production build

```bash
cd webui && npm install && npm run build
```

Output: `src/triagekit/web/static/app/` → **http://127.0.0.1:8000/app/**

## JSON API

- `POST /api/triage` — repo, number
- `POST /api/scan` — target, no_cve, no_agent
- `POST /api/webscan` — url, no_paths, no_agent
- `GET /api/health`
