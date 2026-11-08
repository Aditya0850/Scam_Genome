# TrustLens (Scam Genome)

A deterministic threat classification engine for URL and message (SMS/email) scam detection with evidence-backed assessments, LLM explainability, and tamper-evident report integrity via local hash-chained ledger or optional on-chain anchoring.

---

## Problem

Online scams—phishing links, smishing messages, social-engineering lures—are pervasive and evolving. Security teams and end users lack transparent, deterministic tools that:

- Show **exactly which checks ran** and **what evidence each produced**
- Separate **observed facts** (TLS cert validity, header presence, brand-in-subdomain) from **assumptions** (AI verdicts, reputation scores)
- Provide **coverage metrics** so gaps in analysis are visible (e.g., "threat intel unavailable," "fetch blocked by SSRF protection")
- Preserve **tamper-evident report integrity** without storing raw URLs or PII on-chain

Existing solutions often rely on black-box reputation APIs or AI classifiers that output a score without an auditable trail.

---

## Solution

TrustLens runs a **9-module deterministic pipeline** against a URL or message text. Each module emits findings with `severity`, `confidence`, `weight`, and `source`. A scoring engine aggregates weights (excluding `INFO` severity) into a 0–100 risk score, maps it to a classification (`low_risk` → `confirmed_malicious` → `inconclusive`), and records which checks ran vs. were skipped.

**Key guarantees:**

| Guarantee | Implementation |
|-----------|----------------|
| **SSRF-safe fetch** | Separate A/AAAA DNS resolution, IP allowlist (blocks RFC1918, loopback, link-local, multicast, reserved), per-hop redirect re-validation, 64 KB body cap, 5 s timeout |
| **Prompt-injection isolation** | All untrusted data wrapped in `<untrusted_evidence>` XML tags; system prompt forbids following instructions inside; deterministic fallback generated first; LLM never mutates classification/score/findings |
| **TLS weight = 0** | TLS findings always emit `Severity.INFO` (weight 0)—valid cert ≠ legitimate site |
| **Off-chain PII hashing** | Raw URLs, messages, emails, phones, UPI IDs never stored on-chain; only `SHA-256(target)` fingerprint committed |
| **Campaign correlation privacy** | Correlation via hashed indicators (domain, IP, UPI, phone)—no PII exposed |

**Frontend workspace** provides:
- Landing page with live demo mode (local simulation, clearly labelled)
- Dashboard: Overview analytics, URL Intelligence scanner, Message Analysis, Threat Reports history, On-Chain Verification
- Auth flow (sign-in/register) for workspace persistence
- Motion respects `prefers-reduced-motion`; custom cursor effects disabled on touch devices

---

## Demo Links and Screenshot

| Item | Status |
|------|--------|
| Live demo | **Pending** — not deployed |
| GitHub repository | `https://github.com/<owner>/Scam_Genome` (replace with actual URL) |
| Screenshot | **Not available** — no screenshots committed to repository |

> **Note**: The frontend runs in `VITE_DEMO_MODE=true` by default, using a local simulation that does **not** call the backend. Set `VITE_DEMO_MODE=false` and configure `VITE_API_BASE_URL` to connect to a running FastAPI instance.

---

## Tech Stack

| Layer | Technologies |
|-------|--------------|
| **Backend** | Python 3.12+, FastAPI, uvicorn, pydantic, httpx, dnspython, cryptography, tldextract, idna, rapidfuzz, python-dotenv |
| **Frontend** | React 18, Vite, TypeScript, Tailwind CSS, Framer Motion, react-spring/web, spring-text-engine, GSAP, lucide-react |
| **Smart Contract** | Solidity (ThreatRegistry.sol), Forge/Foundry for build/deploy |
| **Database** | SQLite (local file `trustlens.db`) |
| **Testing** | pytest + pytest-asyncio (backend), Playwright (frontend E2E) |
| **LLM Explainability (optional)** | Groq API, NVIDIA API (fallback chain with 6 s timeout) |
| **Threat Intel (optional)** | URLhaus API |
| **On-Chain (optional)** | EVM RPC (Anvil, Geth, etc.), private key for signing |

---

## Architecture

### Backend Pipeline (9 Modules)

```
Input: URL or Message Text
         │
         ▼
┌──────────────────────────────────────────┐
│ 1. Normalisation                         │  IDNA UTS-46, tldextract, IP handling
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 2. Threat Intel                          │  Local feed + URLhaus (TI_CRITICAL*)
└──────────────────────────────────────────┘
         │  (skip live checks if TI_CRITICAL)
         ▼
┌──────────────────────────────────────────┐
│ 3. Lexical Analysis                      │  Phishing patterns: IP host, punycode,
│                                          │  mixed scripts, brand subdomain, combo-squat,
│                                          │  typosquat, deep subdomains, suspicious TLDs,
│                                          │  lure keywords
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 4. Safe Fetch                            │  SSRF-protected: DNS A/AAAA, IP allowlist,
│                                          │  redirect chain validation, 64 KB body cap
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 5. TLS Analysis                          │  Cert validity, hostname/SAN match,
│                                          │  weak keys, distrusted CAs (weight=0)
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 6. Security Headers                      │  HSTS, CSP, X-Frame-Options,
│                                          │  X-Content-Type-Options
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 7. Scoring Engine                        │  Sum weights (INFO excluded),
│                                          │  TI_CRITICAL → confirmed_malicious,
│                                          │  coverage < 0.5 → inconclusive
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 8. Campaign Correlation                  │  SQLite persistence, report hashing,
│                                          │  shared domain/IP/UPI/phone indicators
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 9. Evidence-Grounded Explainability      │  Prompt-injection guard
│                                          │  (<untrusted_evidence>), deterministic
│                                          │  fallback, LLM chain (Groq→NVIDIA)
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ 10. On-Chain Anchoring (Module 9)        │  ThreatRegistry.sol + local hash-chained
│                                          │  ledger, SHA-256 commitments
└──────────────────────────────────────────┘
```

### Frontend Structure

```
src/
├── App.jsx              # Routes: landing / auth / dashboard (overview, url-scanner,
│                        # message-scanner, reports, verification)
├── main.jsx             # Entry point
├── styles.css           # Tailwind + custom CSS (ambient grid, orbs, cursor FX)
└── trustlens/           # (Python package, not frontend)
```

### API Endpoints (Backend)

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness probe |
| `POST /api/check-url` | Core URL assessment (returns full `Assessment`) |
| `POST /api/check-message` | Core message assessment |
| `GET /api/reports` | List recent reports |
| `GET /api/reports/{id}` | Retrieve full report |
| `POST /api/reports/{id}/anchor` | Anchor report on-chain / local ledger |
| `GET /api/reports/{id}/verify` | Verify cryptographic integrity |
| `POST /api/scan/url` | Frontend-compatible URL scan |
| `POST /api/scan/message` | Frontend-compatible message scan |
| `POST /api/reports/{id}/register` | Frontend alias for anchor |
| `GET /api/reports/{id}/verify` | Frontend-compatible verify |

---

## Setup and Run Steps

### Prerequisites
- Python 3.12+
- `uv` (recommended) or `pip`
- Node.js 18+
- Optional: EVM RPC node (Anvil, Geth) for on-chain anchoring

### Backend

```bash
# Clone and enter directory
cd Scam_Genome

# Install dependencies
uv sync
# or: pip install -e .

# Configure environment (copy .env.example to .env and edit)
cp .env.example .env
# Required for on-chain (optional):
# RPC_URL=http://127.0.0.1:8545
# CONTRACT_ADDRESS=0x...
# PRIVATE_KEY=0x...
# Optional LLM keys:
# GROQ_API_KEY=gsk_...
# NVIDIA_API_KEY=nvapi_...
# Optional threat intel:
# URLHAUS_API_KEY=...
# Offline mode (deterministic, no network):
# OFFLINE_MODE=1

# Run development server
uv run uvicorn trustlens.api:app --reload --port 8000

# Run production server
uv run uvicorn trustlens.api:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
# From repository root
npm install

# Configure (copy .env.example to .env and edit)
cp .env.example .env
# VITE_API_BASE_URL=http://127.0.0.1:8000
# VITE_DEMO_MODE=true  # Set false when backend is ready

# Run development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

### Smart Contract (Optional)

```bash
cd contracts
forge build
forge create contracts/ThreatRegistry.sol:ThreatRegistry \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY
# Note deployed address and set CONTRACT_ADDRESS in backend .env
```

### Run Tests

```bash
# Backend tests
uv run pytest -q

# Specific modules
uv run pytest tests/test_lexical.py -v
uv run pytest tests/test_pipeline.py -v
uv run pytest tests/test_chain.py -v
# ... (13 test modules total)

# Generate demo report
uv run python scripts/run_demo_cases.py
# Output: docs/TESTING_REPORT.md
```

> **Current test status**: 196 passed, 1 failed (`test_pipeline_runs_all_checks` — TLS check connects to real `example.com` instead of using mock; see issue in test file).

---

## Disclosures

### Libraries & Frameworks
- **Backend**: FastAPI, uvicorn, pydantic, httpx, dnspython, cryptography, tldextract, idna, rapidfuzz, python-dotenv, pytest, pytest-asyncio
- **Frontend**: React, Vite, TypeScript, Tailwind CSS, Framer Motion, react-spring/web, spring-text-engine, GSAP, lucide-react
- **Smart Contract**: Solidity, Forge/Foundry
- **Database**: SQLite (stdlib `sqlite3`)

### Templates / Boilerplates
- No external templates or boilerplates identified. Frontend is custom-built with Vite + React. Backend is custom FastAPI application.

### AI Tools Used
- **Claude Code** (Anthropic) — used for development assistance, code review, test debugging, and documentation tasks during this project.

---

## Track

**Security / Threat Intelligence / Web3** — TrustLens is a deterministic web threat detection engine with optional blockchain anchoring for report integrity. It targets security teams, fraud analysts, and developers building safety tooling for URLs and messaging channels.

### Implemented vs. Experimental

| Feature | Status |
|---------|--------|
| 9-module deterministic pipeline | ✅ Implemented |
| SSRF-safe fetch with IP allowlist | ✅ Implemented |
| Threat intel (local + URLhaus) | ✅ Implemented (URLhaus requires API key) |
| Lexical analysis (20+ patterns) | ✅ Implemented |
| TLS analysis (weight=0 rule) | ✅ Implemented |
| Security headers inspection | ✅ Implemented |
| Campaign correlation (SQLite) | ✅ Implemented |
| LLM explainability (Groq→NVIDIA fallback) | ✅ Implemented (requires API keys) |
| Prompt-injection guard | ✅ Implemented |
| Local hash-chained ledger | ✅ Implemented |
| On-chain anchoring (ThreatRegistry.sol) | ✅ Implemented (requires RPC + contract deploy) |
| Frontend dashboard (5 tabs) | ✅ Implemented |
| Demo mode (local simulation) | ✅ Implemented |
| Auth flow (UI only, no backend) | ⚠️ Simulated (no real auth backend) |
| Live demo deployment | ❌ Pending |
| End-to-end test suite | ⚠️ Partial (backend only) |

### Blockchain / Local-Ledger Limitations
- **Local ledger**: File-based hash chain (`trustlens_ledger.jsonl`) — tamper-evident only within a single machine/process; not distributed.
- **On-chain**: Requires deployed `ThreatRegistry.sol`, funded account, and RPC endpoint. Gas costs apply. Only the `SHA-256(target)` fingerprint and canonical report hash are stored on-chain—**never raw URLs, messages, or PII**.
- **Verification**: Confirms the report content matches the anchored commitment. It does **not** validate the ground-truth correctness of the original assessment.

---

## License

MIT License — see [LICENSE](LICENSE) for details.