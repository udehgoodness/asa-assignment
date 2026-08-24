# Remediation Plan — Deferred Findings

Covers every finding in `docs/findings.md` **not** fixed in code (VT-06 through VT-12, plus VT-15 from the container scan). For each: residual risk, effort to remediate, and compensating controls that exist today.

---

## VT-06 — Vulnerable dependencies
**Residual risk**: running `cryptography==38.0.1` (20 CVEs — memory-safety bugs, PKCS12 parsing crashes, a TLS RSA-padding-oracle decrypt bug), `python-jose==3.3.0` (5 CVEs), and `starlette==0.27.0` (9 CVEs, transitive via `fastapi==0.104.1`) means known, patched vulnerabilities remain live in the dependency tree.
**Effort**: moderate, not trivial — `fastapi==0.104.1` pins a compatible `starlette` version, so fixing the `starlette` CVEs means bumping `fastapi` too, which needs regression testing across every route (response models, middleware ordering, the `TrustedHostMiddleware` added in Task 1). `python-jose` → `3.4.0` should be verified against the VT-01 fix (`algorithms=["HS256"]` only). Estimate: half a day, mostly regression testing, not code changes. Bundling it into this already-large remediation PR would make the diff harder to review.
**Compensating controls**: the most actionable of these CVEs (the `python-jose` algorithm-confusion bug) is substantially blunted by the VT-01 fix — `"none"` is no longer in the accepted algorithms list, and the library itself has no working `alg: none` key handler regardless. `cryptography`'s riskiest bugs (PKCS12 parsing, TLS padding oracle) require code paths this app doesn't exercise (no PKCS12 handling, no TLS termination in-process). Recommend a scheduled, tested dependency-upgrade pass as its own follow-up PR.

## VT-07 — Unauthenticated `/notify` + webhook SSRF leaking the internal service key
**Residual risk**: if the "internal network only" assumption behind `notify/src/index.js`'s `/notify` endpoint is ever violated (misconfigured ingress, compromised pod, overly permissive network policy), anything that can reach it can trigger webhook fan-out with no auth, or register its own URL via the also-unauthenticated `POST /webhooks` to harvest the internal `SERVICE_KEY` or pivot to internal-only addresses (SSRF).
**Effort**: moderate (roughly 2–4 hours) — requires adding shared-secret auth on `/notify` (validated against `SERVICE_KEY`), plus URL validation on webhook registration (reject private/link-local IP ranges, restrict to `https`). Deferred because the assignment brief explicitly states `notify/` needs no changes for this submission, and because the primary control belongs at the infrastructure layer regardless of in-app auth.
**Compensating controls**: Task 4's Helm `NetworkPolicy` restricts ingress to the notify service so only the Python API's pod can reach it — this is the control actually load-bearing today, not anything in the notify code itself. The service also has no public ingress route.

## VT-08 — Permissive CORS
**Residual risk**: the custom CORS middleware reflects any `Origin` header and sets `Access-Control-Allow-Credentials: true` unconditionally. Low real exploitability today since auth is bearer-token-based (no ambient cookie credential for a cross-origin page to ride on), but it's a live landmine for the moment anything — a future frontend, a debugging shortcut — starts relying on cookies.
**Effort**: trivial (~15 minutes) — replace the reflect-any-origin logic with an explicit allow-list (config-driven, defaulting to the real frontend origin(s) in production and `localhost` variants for dev). Deferred purely for PR scope/time-boxing, not because it's hard — a strong candidate for the very next small fix.
**Compensating controls**: no cookie-based auth today, so there's no ambient credential currently exposed by this gap.

## VT-09 — Stack traces returned to API clients
**Residual risk**: the global exception handler returns `traceback.format_exc()` and the raw exception message to any caller, aiding attacker reconnaissance (file paths, library versions, query fragments) and occasionally leaking sensitive values embedded in exception messages.
**Effort**: trivial (~15–30 minutes) — return a generic `{"error": "internal server error"}` body, keep logging the full traceback server-side only (already happening via `logger.error`, just stop also echoing it to the client). Deferred for the same PR-scoping reason as VT-08.
**Compensating controls**: no arbitrary code execution is enabled by this, purely information disclosure; the server-side log entry (with full traceback) is preserved regardless, so debuggability isn't lost by fixing it — there's no good reason this stays open long, it's just outside this PR's cut line.

## VT-10 — No rate limiting on `/auth/login`
**Residual risk**: unlimited login attempts with no lockout or delay enable credential stuffing / brute force against user accounts.
**Effort**: moderate (~2–3 hours) to build well in-app on a single SQLite instance without a shared cache — the share-link lockout (Task 1) is a reasonable template, but a proper multi-replica-safe version needs a shared store (Redis, or a dedicated table), not a quick copy-paste.
**Compensating controls**: bcrypt's hashing cost already imposes some per-attempt throttling. Recommended path is an ingress/API-gateway-level rate limit (ties into Task 4's infrastructure) that applies uniformly across all endpoints, not just login — better return on effort than an in-app, login-only mechanism.

## VT-11 — `ecdsa==0.19.2` Minerva timing side-channel (no fix available)
**Residual risk**: `CVE-2024-23342` — signing-key nonce leakage via timing during `sign_digest()`. No released fix exists for this package.
**Effort**: not fixable via a version bump. Removing `ecdsa` outright would mean replacing or vendoring `python-jose`'s ECDSA backend, or migrating off `python-jose` entirely — disproportionate effort for a code path this app never invokes.
**Compensating controls**: the app's JWTs use `HS256` exclusively (symmetric, not ECDSA) — `ecdsa`'s vulnerable `sign_digest()` path is a transitive dependency of `python-jose` that current app logic never calls. Track for removal if `python-jose` is ever replaced; no action needed while `HS256`-only holds.

## VT-12 — `python-multipart==0.0.6` CVEs
**Residual risk**: DoS via malformed multipart parsing, plus a path-traversal bug gated behind a non-default config (`UPLOAD_DIR`/`UPLOAD_KEEP_FILENAME=True`) this app doesn't set.
**Effort**: a version bump is trivial in isolation but tied to the same `fastapi`/`starlette` compatibility-testing pass as VT-06.
**Compensating controls**: the app has zero file-upload endpoints — `python-multipart` is present only as a FastAPI form-handling dependency, so the vulnerable parsing paths are never invoked by any request, legitimate or attacker-supplied, today.

## VT-15 — Base image OS packages carry known CVEs
**Residual risk**: 9 Critical and 66 High severity CVEs in Debian 12 packages pulled in by `python:3.11.10-slim-bookworm` (`reports/container.trivy.json`). Unlike an application dependency, these aren't something this project's code introduced — they're the OS patch backlog of an official, actively-maintained base image as of the pinned digest.
**Effort**: not a one-time fix. The Dockerfile pins the base image by digest for build reproducibility, which is good practice but means it will *never* pick up new OS security patches until someone deliberately re-pins to a newer digest. Real remediation is a recurring process: a scheduled job (weekly, say) that checks for a newer `python:3.11-slim-bookworm` digest, rebuilds, re-scans, and re-pins — effort is in setting up that automation once (a few hours), not in this PR.
**Compensating controls**: the container runs as a non-root user with all Linux capabilities dropped, `allowPrivilegeEscalation: false`, and (in the Helm deployment) a read-only root filesystem — none of these vulnerable OS packages are reachable through the app's own network-facing interface, since nothing in the app shells out to them. Realistic exploitation would require an attacker who already has a foothold via some other vulnerability looking to escalate or escape the container, not a standalone remote path. Recommend setting up the automated base-image-refresh job as a near-term follow-up rather than deferring indefinitely, since this category of risk only grows over time without one.
