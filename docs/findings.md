# Security Findings — VulnTracker

**Status: v1** — covers SAST, SCA, and manual review. Container image and IaC scan results will be appended to this document once Task 4 (Dockerfile + Helm chart) lands, since those scans require artifacts that don't exist yet.

**Context that shapes every severity/impact call below**: VulnTracker exists to store and track *other systems'* unpatched vulnerabilities on behalf of its customers. A breach of this app doesn't just leak "some data" — it hands an attacker a prioritized map of exploitable weaknesses in each customer's actual infrastructure, plus (via the notification/webhook layer) live signals about when new weaknesses are found. Findings that expose scan data or allow account takeover are rated with that in mind, not just against generic CIA-triad defaults.

**Tools used**: [`bandit`](https://github.com/PyCQA/bandit) 1.9.4 (SAST, `bandit -r app/`) and [`pip-audit`](https://github.com/pypa/pip-audit) 2.10.1 (SCA, `pip-audit -r requirements.txt`). Raw output: `reports/sast.bandit.json`, `reports/sca.pip-audit.json`.

## Summary

| ID | Finding | Type | Severity | Code | Status |
|----|---------|------|----------|------|--------|
| VT-01 | JWT decode accepts `alg: none` | Manual | **Critical** | Starter | Open |
| VT-02 | SQL injection in scan search | SAST (bandit) + Manual | **Critical** | Starter | Open |
| VT-03 | Hardcoded secrets in source | SAST (bandit, partial) + Manual | High | Starter | Open |
| VT-04 | IDOR / missing owner scoping on `GET /scans/{id}` and `GET /scans/search` | Manual | High | Starter | Open |
| VT-05 | Plaintext password logging on login | Manual | High | Starter | Open |
| VT-06 | Vulnerable dependencies (cryptography, python-jose, starlette, fastapi) | SCA (pip-audit) | High | Starter | Open |
| VT-07 | Unauthenticated `/notify` + webhook SSRF leaking internal service key | Manual | High | Starter | Open |
| VT-08 | Permissive CORS (reflects any `Origin`, credentials allowed) | Manual | Medium | Starter | Open |
| VT-09 | Stack traces returned to API clients | Manual | Medium | Starter | Open |
| VT-10 | No rate limiting on `/auth/login` | Manual | Medium | Starter | Open |
| VT-11 | `ecdsa` Minerva timing side-channel (no fix available) | SCA (pip-audit) | Medium | Starter | Open |
| VT-12 | `python-multipart` CVEs (DoS / path traversal in unused code paths) | SCA (pip-audit) | Low | Starter | Open |
| VT-13 | Share-link password passed as a GET query parameter | Manual (identified during Task 1 design) | Low | Task 1 | Open (compensating controls documented) |
| VT-14 | Unvalidated password length causes uncaught exception (500 + stack trace) | Manual (found while designing the VT-02 fix) | Medium | Starter + Task 1 | Open |

`bandit` also flagged the literal string `"bearer"` in `main.py` (OAuth2 token type) as a possible hardcoded password — a false positive, not listed above.

---

## Critical

### VT-01 — JWT decode accepts `alg: none`
**Type**: Manual — `app/auth.py:38`, `jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"])`.
**Severity: Critical.** `"none"` in the accepted algorithms list means a token with `{"alg": "none"}` and an empty signature is accepted as valid — no key, no signature, no server secret required. Anyone can mint a JWT for `{"sub": "any-username"}` and be authenticated as that user, including other customers' accounts.
**Business impact**: complete authentication bypass. An attacker doesn't need to steal a password or a signing key — they construct the token by hand. Combined with VT-04 (IDOR), this is a direct path to reading every customer's vulnerability data.
**Cross-reference**: `pip-audit` independently flagged `python-jose` for **CVE-2024-33663**, an algorithm-confusion vulnerability in the same library (see VT-06) — the library itself has a history of this exact bug class, and the app's own configuration makes it strictly worse by explicitly opting in to `"none"`.

### VT-02 — SQL injection in scan search
**Type**: SAST (bandit `B608`, `app/database.py:23`) + Manual confirmation.
**Severity: Critical.** `search_scans_by_query` builds SQL with an f-string directly from user input (`GET /scans/search?q=...`) and executes it via `db.execute(text(sql))`. No parameterization.
**Business impact**: an authenticated user (any registered account, no special privilege needed) can read arbitrary rows from the database — every user's scans across every account, password hashes, and (as of Task 1) the `shared_links` table including `token_hash`/`password_hash` values. It also undermines the token-hashing design in Task 1: hashing the share token only protects against *offline* DB theft, not an *online* SQL injection query against the same DB via this endpoint.

---

## High

### VT-03 — Hardcoded secrets in source
**Type**: SAST (bandit `B105`, flagged `SECRET_KEY` and `DB_PASSWORD` in `app/config.py`; did not flag `ADMIN_API_KEY`, whose name doesn't match its "password"-like regex) + Manual review (also found `notify/src/config.js: SERVICE_KEY`).
**Severity: High.** `SECRET_KEY` signs every JWT issued by the app — anyone with read access to the repository (contractors, CI logs, a future public fork, a leaked laptop) can forge valid tokens for any user, indefinitely, without ever touching the running system. `DB_USER`/`DB_PASSWORD`/`ADMIN_API_KEY` are, on inspection, **unused dead code** — SQLite needs no credentials and nothing in the codebase reads `ADMIN_API_KEY` — but a hardcoded value with a realistic "prod" naming convention (`sk-vt-prod-...`) is exactly the kind of thing a future engineer assumes is live and load-bearing, and copies into a script or a Slack message without a second thought.
**Business impact**: silent, permanent authentication bypass (via the JWT key) that requires no interaction with the live service to exploit, plus a standing risk that the unused-but-realistic-looking keys get mistaken for real credentials and propagated elsewhere.

### VT-04 — IDOR / missing owner scoping on `GET /scans/{id}` and `GET /scans/search`
**Type**: Manual — `app/main.py`, `app/database.py`. `list_scans`, `update_scan`, and `delete_scan` all filter by `owner_id == current_user.id`; `get_scan` does not. The same gap exists in `search_scans_by_query` (`app/database.py`) — its SQL has no `owner_id` clause at all, and `main.py`'s `/scans/search` endpoint never passes `current_user` into it, so a search returns matches across *every* user's scans, not just the caller's. Found while designing the fix for VT-02 (the search endpoint's SQL injection) — parameterizing that query surfaced that it was never scoped to begin with.
**Severity: High.** Any authenticated user — including a brand-new self-registered account — can read any other user's scan directly by ID, or indirectly by searching for it.
**Business impact**: direct cross-tenant leak of exactly the data this product is built to protect: which systems are vulnerable, to what, and whether they've been fixed yet. The search endpoint is arguably the easier path to exploit — an attacker doesn't even need to know or guess a valid scan ID, just a common enough search term (e.g. `q=CVE`) to sweep other tenants' findings.

### VT-05 — Plaintext password logging on login
**Type**: Manual — `app/main.py`, both the login-attempt log line and the failed-login log line include `payload.password` verbatim.
**Severity: High.** Every login attempt — successful or not — writes the user's plaintext password to the application log, on every request, by design (not an accidental debug leftover left running).
**Business impact**: anyone with log access (ops staff, a log-aggregation SaaS vendor, a misconfigured log bucket, a backup) can harvest live, working credentials continuously. Because password reuse is the norm, this also risks accounts outside this system.

### VT-06 — Vulnerable dependencies
**Type**: SCA (pip-audit) — 46 known CVEs across 7 packages (`reports/sca.pip-audit.json`).
**Severity: High**, driven by `cryptography==38.0.1` (20 CVEs — bundles an outdated statically-linked OpenSSL, plus PKCS12 parsing crashes and a TLS RSA-padding-oracle decrypt bug) and `python-jose==3.3.0` (5 CVEs, including the algorithm-confusion bug referenced in VT-01 and a "JWT bomb" decompression DoS). `starlette==0.27.0` (9 CVEs, transitive via `fastapi==0.104.1`) and `fastapi` itself round this out.
**Business impact**: `cryptography` underpins the password-hashing and JWT-signing stack this app's entire auth model depends on — running a 3-year-old version with known memory-safety and crypto-parsing bugs is direct exposure of the trust boundary, not a peripheral dependency issue. `python-multipart` (VT-12) and `ecdsa` (VT-11) are broken out separately below because their real-world exploitability in *this specific app* is much lower — interpretation matters more than the raw CVE count here. The 7th flagged package, `pytest==7.4.3` (1 CVE, `CVE-2025-71176`), is a predictable-`/tmp`-directory local-privilege issue relevant only to a shared local machine, and `pytest` is a dev/test-only dependency that never ships in the running app or its container image — no action needed beyond a routine version bump.

### VT-07 — Unauthenticated `/notify` + webhook SSRF leaking the internal service key
**Type**: Manual — `notify/src/index.js` (`POST /notify` has a code comment stating it's "assumed to be reachable only from internal network; no authentication applied") and `notify/src/dispatcher.js` (every dispatch attaches `X-Service-Key: config.SERVICE_KEY` to a POST at the webhook's registered `url`, which is accepted from `POST /webhooks` with no validation — no scheme restriction, no block on internal/link-local addresses).
**Severity: High.** Two compounding issues: (1) if the "internal network only" assumption about `/notify` is ever wrong — a misconfigured ingress, a container escape, a permissive network policy — anything that can reach it can trigger arbitrary webhook fan-out with no auth; (2) anyone who can call `POST /webhooks` (also unauthenticated) can register **their own** URL and receive a live copy of the internal `SERVICE_KEY` on every dispatch, or point the URL at an internal-only address (cloud metadata endpoint, admin panel) to use the notify service as an SSRF proxy.
**Business impact**: this directly informed the Task 4 requirement to "restrict network ingress to only what is required" — the app's own design assumes a network boundary that has to actually be enforced at the infrastructure layer, because nothing in the code enforces it.

---

## Medium

- **VT-08 — Permissive CORS** (Manual, `app/main.py`): the custom CORS middleware reflects whatever `Origin` header the caller sends and sets `Access-Control-Allow-Credentials: true` for every response. Today's impact is limited because auth is bearer-token-based, not cookie-based, so there's no ambient credential for a cross-origin page to ride on — but it's an unforced error, and becomes critical the moment anything (a future frontend, a debugging shortcut) starts relying on cookies.
- **VT-09 — Stack traces returned to clients** (Manual, `app/main.py`, global exception handler): unhandled exceptions return `traceback.format_exc()` and the raw exception message in the JSON body. Aids attacker reconnaissance (file paths, library versions, query fragments) and risks leaking sensitive values that end up inside exception messages.
- **VT-10 — No rate limiting on `/auth/login`** (Manual): unlimited login attempts, no lockout, no delay. Enables credential stuffing / brute force against user accounts. Notably, the Task 1 share-link endpoint *does* implement exactly this kind of protection (5 attempts → 15-minute lockout) — the new feature meets a bar the existing auth flow doesn't.
- **VT-11 — `ecdsa==0.19.2` Minerva timing side-channel** (SCA (pip-audit), CVE-2024-23342, no fix version published): leaks signing-key nonces via timing during `sign_digest()`. Lower real-world urgency here than the CVE alone suggests — this app's JWTs use `HS256` (symmetric), so the vulnerable ECDSA signing path is a transitive dependency of `python-jose` that isn't actually exercised by current app logic. Still worth tracking since it can't be "upgraded away."
- **VT-14 — Unvalidated password length causes an uncaught exception** (Manual, found while designing the VT-02 fix, `app/main.py`: `UserRegister.password`, `UserLogin.password`, `ShareCreate.password`): none of these fields cap input length. Tested directly against `get_password_hash()` with a 100,000-character password — it doesn't hash-then-truncate (no CPU-cost DoS), it raises `passlib.exc.PasswordSizeError` immediately, uncaught, which propagates to the global exception handler (VT-09) and returns a 500 with a full stack trace to an unauthenticated caller (`POST /auth/register`) or an authenticated one (`POST /scans/{id}/share`). Low effort, clean fix — a `max_length` constraint on the Pydantic field rejects it with a normal 422 before it ever reaches bcrypt.

## Low

- **VT-12 — `python-multipart==0.0.6` CVEs** (SCA (pip-audit), 9 entries): mostly DoS via malformed multipart parsing and a path-traversal bug gated behind a non-default `UPLOAD_DIR`/`UPLOAD_KEEP_FILENAME` config. The app has no file-upload endpoints (`python-multipart` is present only as a FastAPI form-handling dependency) — real exposure today is minimal, but it's dead weight worth removing or upgrading rather than justifying indefinitely.
- **VT-13 — Share-link password as a GET query parameter** (Manual, identified during Task 1 design, `GET /share/{token}`): query strings are more likely to be captured in access logs, browser history, and proxy logs than a POST body would be. This is the interface the assignment specifies (`GET` + `password` query parameter), so it's a deliberate, spec-driven trade-off rather than an oversight — documented here for completeness and expanded in `docs/remediation-plan.md`.
