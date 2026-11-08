# TrustLens Wave 1 spec

Repo: `Scam_Genome`. Package `trustlens`, `src/` layout, Python >=3.12.
Keep the existing `LICENSE` untouched.

## Working rules (for the coding agent)
- Do ONLY the step you are asked to do. Stop after its tests pass.
- Keep each file under 150 lines where possible. Split big files and big test files.
- One test file per module (`tests/test_<module>.py`). No single giant test file.
- Never edit a test just to make it pass. If a test looks wrong, say why first.
- Run `uv run pytest -q <that step's test file>` and report the result.

## Non-negotiable security and design rules
1. Deterministic engine decides classification (`low_risk`, `suspicious`, `high_risk`, `confirmed_malicious`, `inconclusive`). The LLM only explains.
2. A valid TLS cert is `Severity.INFO` with `weight=0`. It never lowers the risk score and never proves legitimacy.
3. `confirmed_malicious` is ONLY assigned when an authoritative threat-intel check matches.
4. Too many failed or unavailable checks (`coverage < 0.5` with no high/confirmed signal) -> `inconclusive`.
5. SSRF protection in `safefetch.py` is mandatory:
   - resolve DNS via `dnspython`
   - unwrap IPv4-mapped IPv6 (`addr.ipv4_mapped`)
   - block private, loopback, link-local, multicast, reserved, unspecified, CGNAT (`100.64.0.0/10`) and cloud metadata (`169.254.169.254`)
   - if ANY resolved IP in the RRset is non-global, raise `SSRFBlockedError`
   - `follow_redirects=False`, re-validate DNS/IP on every redirect hop (max 3 hops)
   - 5s timeout, cap body read at 64KB, text/html or json only

## Step 1: project setup, models, config
- `pyproject.toml` for `trustlens` (hatchling or setuptools), Python >=3.12, with
  `[tool.pytest.ini_options]` `testpaths = ["tests"]`, `asyncio_mode = "auto"`.
- Run:
  `uv add fastapi "uvicorn[standard]" pydantic httpx dnspython cryptography tldextract idna rapidfuzz python-dotenv`
  `uv add --dev pytest pytest-asyncio`
  (`anthropic` and `web3` are deferred to the explanation and contract waves.)
- Create dirs: `src/trustlens/checks/`, `src/trustlens/message/`, `tests/`, `data/fixtures/`, `contracts/`, `frontend/`, `docs/`.
- `.gitignore`: `.env`, `.venv/`, `__pycache__/`, `*.db`, `node_modules/`, `dist/`, `.pytest_cache/`.
- `src/trustlens/__init__.py` and `src/trustlens/models.py` (FROZEN CONTRACT):
  - Enums `Classification` (`low_risk`, `suspicious`, `high_risk`, `confirmed_malicious`, `inconclusive`) and `Severity` (`info`, `low`, `medium`, `high`, `critical`).
  - `Finding`: `id`, `check`, `title`, `severity`, `evidence` (min_length=1, max_length=1000), `source` (min_length=1), `confidence` (0.0..1.0, default 0.5), `weight` (int 0..100, default 0), `impact` (str | None = None), `recommendation` (str | None = None). `ConfigDict(str_strip_whitespace=True, extra="forbid")`.
  - `CheckStatus`: `check` (min_length=1), `ran` (bool), `reason` (str | None = None).
  - `FetchResult`: `ok` (bool), `final_url` (str | None), `resolved_ip` (str | None), `status_code` (int | None), `headers` (dict[str, str] = {}), `redirect_chain` (list[str] = []), `body_preview` (str = "", max_length=4096), `findings` (list[Finding] = []), `status` (CheckStatus).
  - `Assessment`: `report_id` (str | None), `kind` (`Literal["url","message"]` = "url"), `target` (str), `classification`, `score` (int 0..100, default 0), `findings`, `checks`, `coverage` (float 0..1), `unavailable_checks` (list[str]), `explanation` (str | None), `limitations` (default `["Absence of known threats is not proof a site is safe.", "A valid TLS certificate does not mean a site is legitimate."]`), `report_hash`, `tx_hash` (str | None), `timestamp` (UTC datetime).
  - `UrlRequest` (`url: str = Field(min_length=3, max_length=2048)`), `MessageRequest` (`text: str = Field(min_length=1, max_length=10000)`).
- `src/trustlens/config.py`: frozen `Settings` dataclass loading env vars `ANTHROPIC_API_KEY`, `URLHAUS_API_KEY`, `RPC_URL` (default `http://127.0.0.1:8545`), `CONTRACT_ADDRESS`, `PRIVATE_KEY`, `DB_PATH` (default `trustlens.db`), `OFFLINE_MODE` (bool, default False). Mask secrets in `__repr__`. Cached `get_settings()`.
- Tests: `tests/test_models.py`, `tests/test_config.py`.

## Step 2: normalise
`src/trustlens/checks/normalise.py`
- Frozen dataclass `NormalisedUrl(original, scheme, host, unicode_host, port, path, query, normalized, registrable_domain, suffix, is_ip, has_userinfo)` and `NormalisationError(ValueError)`.
- `tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=("bank.in",))` so no network calls happen.
- IDNA UTS-46 (`idna.encode(host, uts46=True)`), strip default ports (80/443), detect and strip `userinfo`, reject control chars, whitespace, backslashes, and schemes other than http/https. Schemeless input defaults to `http://`.
- Tests: `tests/test_normalise.py`.

## Step 3: brands and lexical checks
- `data/brands.json`: 30 brands with official registrable domains. Global, Indian banking/UPI (`sbi`, `hdfc`, `icici`, `axisbank`, `kotak`, `paytm`, `phonepe`, `razorpay`, `npci`, `irctc`, `uidai`), and Web3 (`metamask`, `binance`, `coinbase`, `opensea`).
- `src/trustlens/checks/lexical.py`: `async def run(target: NormalisedUrl, settings: Any = None) -> tuple[list[Finding], CheckStatus]`.
- Detections:
  - raw IP host: `LEX_IP_HOST`, HIGH, weight 35
  - `@` userinfo: `LEX_USERINFO_AT`, HIGH, 40
  - mixed Unicode scripts: `LEX_MIXED_SCRIPT`, HIGH, 45; punycode/IDN: `LEX_IDN_PUNYCODE`, MEDIUM, 20
  - brand in subdomain: `LEX_BRAND_SUBDOMAIN`, HIGH, 45
  - brand combo-squat in SLD: `LEX_BRAND_COMBO`, HIGH, 40
  - typosquat via `rapidfuzz.distance.Levenshtein.distance == 1` or de-leeted match (`0->o`, `1->l`, `3->e`, `4->a`, `5->s`, `rn->m`, `vv->w`): `LEX_TYPOSQUAT`, HIGH, 40
  - deep subdomains >= 3 levels: `LEX_DEEP_SUBDOMAIN`, MEDIUM, 15; host length > 75: `LEX_LONG_HOST`, LOW, 10
  - suspicious TLDs (`.xyz .top .click .zip .mov .tk .ml .ga .cf .gq .buzz .icu .work .support`): `LEX_SUSPICIOUS_TLD`, LOW, 15
  - lure keywords (`login signin verify kyc update secure account wallet suspend refund unlock confirm`): `LEX_LURE_KEYWORDS`, MEDIUM, 20
- False-positive guard: never flag brand spoofing, deep subdomains or lure keywords when `target.registrable_domain` is an official brand domain or `target.suffix` is in `{"gov.in","ac.in","edu","gov","mil","bank.in"}`.
- Tests: `tests/test_lexical.py`. HIGH: `paypa1.com/login`, `sbi.co.in.kyc-update.xyz`, `https://google.com@evil.xyz`, a mixed-script punycode host. Zero findings: `https://github.com/login`, `https://sbi.co.in`, `https://adamasuniversity.ac.in`.

## Step 4: safefetch (SSRF guard). Review this one by hand.
`src/trustlens/checks/safefetch.py`
- `SSRFBlockedError(ValueError)`.
- `is_ip_allowed(ip_str: str) -> bool`: blocks private, loopback, link-local, multicast, reserved, unspecified, non-global, CGNAT `100.64.0.0/10`, `169.254.169.254`; unwraps `addr.ipv4_mapped`.
- `async def resolve_and_validate(host: str, is_ip: bool, resolver: Any = None) -> list[str]` using `dns.asyncresolver.Resolver`. If ANY A/AAAA result is not allowed, raise `SSRFBlockedError`.
- `async def run(target, settings=None, transport: httpx.AsyncBaseTransport | None = None, resolver=None) -> FetchResult`: manual redirects, up to 3 hops, re-normalise and re-validate DNS/IP on every hop, body preview capped at 4096 chars (64KB max network read), 5.0s timeout.
- On `SSRFBlockedError` return `FetchResult(ok=False, findings=[Finding(id="FETCH_SSRF_BLOCKED", check="safefetch", title="Target resolves to restricted or private network address", severity=Severity.HIGH, evidence=str(exc), source="safefetch_ssrf_guard", confidence=1.0, weight=0)], status=CheckStatus(check="safefetch", ran=False, reason=str(exc)))`.
- Open decision: `weight=0` here is as originally specified. Decide deliberately whether a private-IP target should add risk.
- Tests: `tests/test_safefetch.py` covering `127.0.0.1`, `169.254.169.254`, `::1`, `::ffff:127.0.0.1`, `10.0.0.1`, `100.64.0.1`, and a 302 from a public IP to `127.0.0.1` using a mocked httpx transport and resolver.

## Step 5: message extraction
`src/trustlens/message/extract.py`
- Extract and refang URLs (`hxxp`, `[.]`), emails, phone numbers and UPI IDs (`handle@bank`, distinguished from emails), with deduplication and caps.
- Tests: `tests/test_extract.py`.
