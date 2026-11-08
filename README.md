# TrustLens: Deterministic Threat Classification Engine

TrustLens is a deterministic threat classification engine with LLM explainability, designed for URL and message (SMS/email) scam detection. It combines static analysis, threat intelligence, safe network fetching, TLS analysis, and security headers inspection — with cryptographic audit trails and optional on-chain anchoring.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        TrustLens Pipeline                       │
├─────────────────────────────────────────────────────────────────┤
│  Input: URL or Message Text                                     │
└──────────────────────┬──────────────────────────────────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Module 1: Normalisation  │  IDNA UTS-46, tldextract, IP handling
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Module 2: Threat Intel   │  Local feed + URLhaus (TI_CRITICAL*)
         └─────────────┬─────────────┘
                       │ (skip live checks if TI_CRITICAL)
         ┌─────────────▼─────────────┐
         │  Module 3: Lexical        │  Phishing patterns, brands, TLDs, lure keywords
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Module 4: Safe Fetch     │  SSRF-protected: DNS A/AAAA, IP allowlist,
         │                           │  redirect chain validation, 64KB body cap
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Module 5: TLS Analysis   │  Cert validity, hostname match, weak keys,
         │                           │  distrusted CAs (weight=0, INFO only)
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Module 6: Headers        │  HSTS, CSP, X-Frame-Options, X-Content-Type-Options
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Scoring Engine           │  Sum weights (INFO excluded), TI_CRITICAL → confirmed_malicious,
         │                           │  coverage < 0.5 → inconclusive
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Campaign Correlation     │  SQLite persistence, shared domain/IP/UPI/phone indicators
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  Evidence-Grounded Explain│  Prompt-injection guard (<untrusted_evidence>),
         │                           │  deterministic fallback, LLM chain (Groq→NVIDIA→Anthropic)
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  On-Chain Anchoring       │  ThreatRegistry.sol + local hash-chained ledger
         │  (Module 7)               │  SHA-256 commitments, privacy-preserving fingerprints
         └───────────────────────────┘
```

## Modules 1–7 Mapping

| Module | Component | File | Purpose |
|--------|-----------|------|---------|
| 1 | Normalisation | `src/trustlens/checks/normalise.py` | URL canonicalisation, IDNA UTS-46, registrable domain extraction |
| 2 | Threat Intel | `src/trustlens/checks/intel.py` | Local feed + URLhaus lookup, `TI_CRITICAL_*` findings |
| 3 | Lexical | `src/trustlens/checks/lexical.py` | Phishing patterns: IP host, punycode, mixed scripts, brand subdomain, combo-squat, typosquat, deep subdomains, suspicious TLDs, lure keywords |
| 4 | Safe Fetch | `src/trustlens/checks/safefetch.py` | SSRF-protected HTTP fetch with DNS resolution, IP allowlist, redirect validation, 64KB cap |
| 5 | TLS Analysis | `src/trustlens/checks/tls.py` | Certificate validity, hostname/SAN matching, weak keys, distrusted CAs (weight=0) |
| 6 | Security Headers | `src/trustlens/checks/headers.py` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| 7 | Campaign Correlation | `src/trustlens/db.py` | SQLite persistence, report hashing, correlation via shared indicators |
| 8 | Explainability | `src/trustlens/explain.py` | Evidence-grounded LLM explanation with prompt-injection guard |
| 9 | On-Chain Verification | `contracts/ThreatRegistry.sol`, `src/trustlens/chain.py` | EVM smart contract + local reproducible ledger |

## Security & Privacy Guarantees

### SSRF Protection (Module 4: Safe Fetch)
- Separate A/AAAA DNS resolution via `dns.asyncresolver`
- IP allowlisting: blocks private (RFC1918), loopback, link-local, multicast, reserved, documentation ranges
- Per-hop redirect validation: every redirect target re-resolved and re-validated
- 64KB response body cap, non-HTML content yields no preview
- 5s total timeout, 2s connect timeout

### Prompt-Injection Isolation (Module 8: Explainability)
- All untrusted data (target URL/message, finding evidence) wrapped in `<untrusted_evidence>` XML tags
- System prompt explicitly forbids following instructions inside `<untrusted_evidence>`
- Deterministic fallback explanation generated first; LLM output never mutates `classification`, `score`, or `findings`
- LLM timeout: 6s with fallback chain (Groq → NVIDIA → Anthropic)

### TLS Weight=0 Rule (Module 5)
- TLS findings always emit `Severity.INFO` with `weight=0`
- Valid certificate ≠ legitimate site (explicit limitation in every explanation)
- Certificate issues (expiry, hostname mismatch, weak keys, distrusted CAs) reported as INFO only

### Off-Chain PII Hashing (Module 9)
- Raw URLs, message content, emails, phones, UPI IDs **never** stored on-chain or in ledger
- Only `target_fingerprint = SHA-256(target)` stored on-chain
- Report hash commits to canonical JSON: `{kind, target_hash, classification, score, finding_ids, timestamp_iso}`

### Campaign Correlation Privacy
- Correlation via hashed indicators (domain, IP, UPI, phone)
- No PII exposed in correlation logic

## REST API Reference

Base URL: `http://localhost:8000` (or deployed endpoint)

All endpoints support CORS (`allow_origins=["*"]`) for frontend integration.

### `GET /health`
Liveness/readiness probe.

**Response:**
```json
{ "status": "ok" }
```

---

### `POST /api/check-url`
Assess a single URL.

**Request:**
```json
{ "url": "https://paypal.phishersite.com/login" }
```

**Response (Assessment):**
```json
{
  "report_id": "uuid",
  "kind": "url",
  "target": "https://paypal.phishersite.com/login",
  "classification": "high_risk",
  "score": 65,
  "findings": [
    {
      "id": "LEX_BRAND_SUBDOMAIN",
      "check": "lexical",
      "title": "Brand name in subdomain",
      "severity": "high",
      "evidence": "Subdomain contains brand: paypal (full host: paypal.phishersite.com)",
      "source": "lexical_analysis",
      "confidence": 0.9,
      "weight": 45,
      "impact": "Attackers use trusted brand names in subdomains to spoof legitimacy",
      "recommendation": "Verify the registrable domain (phishersite.com), not the subdomain"
    }
  ],
  "checks": [
    { "check": "intel", "ran": true },
    { "check": "lexical", "ran": true },
    { "check": "safefetch", "ran": false, "reason": "Skipped live fetch for confirmed malicious target" },
    { "check": "tls", "ran": false, "reason": "Skipped: no fetch response available" },
    { "check": "headers", "ran": false, "reason": "Skipped: no fetch response available" }
  ],
  "coverage": 0.4,
  "unavailable_checks": ["safefetch", "tls", "headers"],
  "explanation": "Verdict: High Risk (Score: 65/100)...",
  "limitations": [
    "Absence of known threats is not proof a site is safe.",
    "A valid TLS certificate does not mean a site is legitimate."
  ],
  "related_reports": [
    { "report_id": "...", "target": "...", "classification": "high_risk", "shared_indicator": "domain:phishersite.com", "created_at": "..." }
  ],
  "report_hash": "0x...",
  "tx_hash": null,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### `POST /api/check-message`
Assess a message text (SMS, email, chat).

**Request:**
```json
{
  "text": "URGENT: Your SBI account blocked. Share OTP 123456. Pay via UPI: user@oksbi. Link: https://sbi-verify.phishersite.com"
}
```

**Response:** Same `Assessment` structure as `/api/check-url` with `kind: "message"` and message-specific findings (`MSG_CREDENTIAL_REQUEST`, `MSG_URGENCY_COERCION`, `MSG_PAYMENT_LURE`, `MSG_IMPERSONATION`).

---

### `GET /api/reports`
List recent assessment reports.

**Query Parameters:**
- `limit` (optional, default: 20)

**Response:**
```json
{
  "reports": [
    {
      "report_id": "uuid",
      "kind": "url",
      "target": "https://...",
      "classification": "high_risk",
      "score": 65,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

### `GET /api/reports/{report_id}`
Retrieve a specific report by ID.

**Response:** Full `Assessment` object (same as check endpoints).

---

### `POST /api/reports/{report_id}/anchor`
Anchor a saved report on-chain (EVM RPC) or in local hash-chained ledger.

**Response:**
```json
{
  "tx_hash": "0x...",
  "report_hash": "0x...",
  "target_fingerprint": "0x...",
  "mode": "local_ledger",
  "block_number": 5,
  "contract_address": null
}
```

**EVM RPC mode** (when `RPC_URL`, `CONTRACT_ADDRESS`, `PRIVATE_KEY` configured):
```json
{
  "tx_hash": "0x...",
  "report_hash": "0x...",
  "target_fingerprint": "0x...",
  "mode": "evm_rpc",
  "block_number": null,
  "contract_address": "0x..."
}
```

---

### `GET /api/reports/{report_id}/verify`
Verify a report's cryptographic integrity and on-chain/ledger commitment.

**Response:**
```json
{
  "report_id": "uuid",
  "stored_hash": "0x...",
  "recomputed_hash": "0x...",
  "on_chain_hash": "0x...",
  "tx_hash": "0x...",
  "target_fingerprint": "0x...",
  "anchored": true,
  "integrity_verified": true,
  "provenance_note": "Cryptographic commitment verifies report integrity and history, not the ground-truth validity of the underlying claim."
}
```

**If not yet anchored:**
```json
{
  "report_id": "uuid",
  "stored_hash": "0x...",
  "recomputed_hash": "0x...",
  "on_chain_hash": null,
  "tx_hash": null,
  "target_fingerprint": "0x...",
  "anchored": false,
  "integrity_verified": true,
  "provenance_note": "..."
}
```

**If tampered after anchoring:**
```json
{
  "integrity_verified": false,
  "recomputed_hash": "0x...",
  "stored_hash": "0x...",
  "on_chain_hash": "0x..."  // original anchored hash
}
```

## Setup

### Prerequisites
- Python 3.11+
- `uv` (recommended) or `pip`
- Optional: EVM RPC node (Anvil, Geth, etc.) for on-chain mode

### Installation
```bash
# Clone and enter directory
cd Scam_Genome

# Install dependencies
uv sync

# Or with pip
pip install -e .
```

### Configuration
Environment variables (`.env` file or shell):

```bash
# Required for on-chain anchoring (optional)
RPC_URL=http://127.0.0.1:8545
CONTRACT_ADDRESS=0x...
PRIVATE_KEY=0x...

# Database
DB_PATH=trustlens.db

# LLM API keys for explanation (optional, falls back to deterministic)
GROQ_API_KEY=gsk_...
NVIDIA_API_KEY=nvapi_...
ANTHROPIC_API_KEY=sk-ant-...

# Threat intel
URLHAUS_API_KEY=...

# Offline mode (deterministic, no network calls)
OFFLINE_MODE=1
```

### Running the API Server
```bash
# Development
uv run uvicorn trustlens.api:app --reload --port 8000

# Production
uv run uvicorn trustlens.api:app --host 0.0.0.0 --port 8000
```

### Deploying the Smart Contract
```bash
# Using Forge (recommended)
cd contracts
forge build
forge create contracts/ThreatRegistry.sol:ThreatRegistry --rpc-url $RPC_URL --private-key $PRIVATE_KEY

# Note the deployed address and set CONTRACT_ADDRESS
```

## Test Commands

### Run All Tests
```bash
uv run pytest -q
```

### Run Specific Test Modules
```bash
# Unit tests for each module
uv run pytest tests/test_lexical.py -v
uv run pytest tests/test_safefetch.py -v
uv run pytest tests/test_tls.py -v
uv run pytest tests/test_intel.py -v
uv run pytest tests/test_headers.py -v
uv run pytest tests/test_scoring.py -v
uv run pytest tests/test_pipeline.py -v
uv run pytest tests/test_message_analyze.py -v
uv run pytest tests/test_message_extract.py -v
uv run pytest tests/test_db_correlation.py -v
uv run pytest tests/test_explain.py -v
uv run pytest tests/test_chain.py -v
```

### Run Demo Cases & Generate Report
```bash
uv run python scripts/run_demo_cases.py
# Output: docs/TESTING_REPORT.md
```

### Quick API Test
```bash
# Health check
curl http://localhost:8000/health

# Check URL
curl -X POST http://localhost:8000/api/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal.phishersite.com/login"}'

# Check message
curl -X POST http://localhost:8000/api/check-message \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Share OTP 123456. Pay via UPI: user@oksbi"}'

# List reports
curl http://localhost:8000/api/reports

# Anchor report
curl -X POST http://localhost:8000/api/reports/{report_id}/anchor

# Verify report
curl http://localhost:8000/api/reports/{report_id}/verify
```

## Classification Reference

| Classification | Code | Description |
|----------------|------|-------------|
| `low_risk` | 0 | No significant findings, score 0–15 |
| `suspicious` | 1 | Low/medium findings, score 15–39 |
| `high_risk` | 2 | High severity findings, score 40–79 |
| `confirmed_malicious` | 3 | `TI_CRITICAL_*` finding present |
| `inconclusive` | 4 | Coverage < 50% (checks skipped/failed) |

## Severity Reference

| Severity | Weight Range | Used For |
|----------|--------------|----------|
| `info` | 0 | TLS valid, informational headers |
| `low` | 1–15 | Missing security headers, urgency keywords |
| `medium` | 16–39 | Payment lures, impersonation, lure keywords |
| `high` | 40–69 | Brand subdomain, credential requests, typosquat |
| `critical` | 70–100 | Threat intel matches (`TI_CRITICAL_*`) |

## License

MIT License — see LICENSE file for details.