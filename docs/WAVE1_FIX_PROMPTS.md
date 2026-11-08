# Wave 1: fix-and-verify prompts (code already exists, do NOT rebuild)

Before each prompt: `git status`, and commit what's there.
Paste ONE prompt at a time. Read the diff (`git diff`) before the next one.

Rules every prompt repeats, because the agent forgets:
- The files already exist under src/trustlens/. Read them first. Do NOT rewrite or recreate a file.
- Make the smallest edit that fixes the named problem. No refactors, no new features.
- Do not change a test to make it pass without telling me why.
- Spec is docs/WAVE1.md. If code and spec disagree, tell me before editing.
- Stop after the task. Do not move on to other files.

---

## 0. Audit the unseen files (read-only)
Read docs/WAVE1.md, then src/trustlens/models.py, config.py, checks/normalise.py and pyproject.toml. Do NOT edit anything. Compare each against the spec and list every mismatch (field names, bounds, defaults, missing validations, wrong dependencies). Output a short list only, then stop.

## 1. lexical.py fixes
Read src/trustlens/checks/lexical.py. Fix ONLY these, with minimal edits:
1. The brands.json path is wrong: it resolves to src/data/ but the file is at <repo root>/data/brands.json. Fix the path.
2. _extract_sld returns the last subdomain label for hosts with subdomains. For www.paypa1.com it must give "paypa1" (first label of target.registrable_domain).
3. The brand-in-subdomain loop also checks the registrable domain's own label, so sbi-login.com fires both LEX_BRAND_SUBDOMAIN and LEX_BRAND_COMBO. Only check labels to the LEFT of the registrable domain. Emit at most one finding per finding ID.
4. The Levenshtein distance == 1 rule must only apply to brand names of 5+ characters, to avoid false positives on short brands like "sbi".
5. Remove the MULTI_LEET entries "cl", "oi", "nn". Keep only rn->m and vv->w, as in the spec.
Then run `uv run pytest -q` if tests exist, and stop.

## 2. brands.json fixes
Read data/brands.json. Fix ONLY: remove the duplicate "coinbase" entry, and remove user-content hosting domains from official_domains (github.io, amazonaws.com, googleusercontent.com, aws.amazon.com). Keep everything else. Stop.

## 3. extract.py fixes
Read src/trustlens/message/extract.py. Fix ONLY these:
1. UPI_PATTERN matches "user@example" out of "user@example.com". Make it not match when the part after the bank handle is followed by ".<letter>", so real emails are never returned as UPI IDs.
2. PHONE_PATTERN has no digit boundaries and matches inside longer digit strings. Add lookarounds so the number is not preceded or followed by another digit.
Do not touch anything else. Stop.

## 4. tests for lexical and extract (not safefetch)
Read the source files first. Write tests/test_lexical.py and tests/test_extract.py. Keep each under 150 lines. Required cases:
- lexical HIGH: paypa1.com/login, www.paypa1.com, sbi.co.in.kyc-update.xyz, https://google.com@evil.xyz, a mixed-script punycode host.
- lexical zero findings: https://github.com/login, https://sbi.co.in, https://adamasuniversity.ac.in.
- extract: user@example.com is an email and NOT a UPI ID; name@oksbi is a UPI ID; hxxp://evil[.]com is refanged to http://evil.com; a 10-digit Indian mobile is found once.
If a test fails, report the failure and the likely cause. Do NOT edit source files or weaken the test. Run `uv run pytest -q tests/test_lexical.py tests/test_extract.py` and stop.

## 5. safefetch.py review (read-only, I will fix it myself)
Read src/trustlens/checks/safefetch.py and docs/WAVE1.md section "Step 4". Do NOT edit any file. Report, as a numbered list with line numbers, every place the code violates the spec or has a bug. Check specifically:
- A and AAAA lookups sharing one try block (a host with no AAAA record gets blocked)
- NXDOMAIN being reported as an SSRF block
- urlparse used in run() but imported only inside another function
- the 64KB cap not being enforced because the full body is already downloaded
- whether the redirect to 127.0.0.1 path actually executes
- DNS being resolved twice (validation, then httpx resolving again)
Stop after the list.

---

## Tests I will write myself (do not delegate)
tests/test_safefetch.py with: 127.0.0.1, 169.254.169.254, ::1, ::ffff:127.0.0.1, 10.0.0.1, 100.64.0.1 blocked; a public host with only A records allowed; a 302 from a public IP to 127.0.0.1 blocked, using a mocked httpx transport and resolver.
