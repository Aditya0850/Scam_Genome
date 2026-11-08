# TrustLens — React frontend

A polished React/Vite starter for a Web Threat Detection & Digital Trust Platform.

## Run locally
1. Install Node.js 18+.
2. `npm install`
3. Copy `.env.example` to `.env` and configure `VITE_API_BASE_URL`.
4. `npm run dev`

## Backend integration contract
The UI is configured to call:
- `POST /api/scan/url` with `{ "url": "https://example.com" }`
- `POST /api/scan/message` with `{ "message": "..." }`
- `POST /api/reports/{reportId}/register` to register a report
- `GET /api/reports/{reportId}/verify` to verify integrity

Set `VITE_DEMO_MODE=false` when the FastAPI backend is ready. In demo mode, the interface uses a clearly labelled local simulation; it does not claim to perform real security analysis.

## Design notes
- Custom cursor and glow follow effects are disabled on touch devices.
- The background is transparent CSS layering over a dark base, not a full-screen opaque image.
- Motion respects `prefers-reduced-motion`.
- Never expose API secrets in frontend environment variables. Keep provider keys on the backend.
