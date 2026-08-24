# Shared Report Link

Implemented feature (Task 1): a scan owner can generate a link to hand a single scan's findings to an external stakeholder (e.g. a customer or auditor), without giving them an account.

| Method | Path                      | Auth                 | Description                                                             |
| ------ | ------------------------- | --------------------- | ------------------------------------------------------------------------ |
| `POST` | `/scans/{scan_id}/share`  | Bearer token (owner)  | Creates a share link for a scan you own. Optional `password` in the body. Returns `{ "share_url": "..." }`. |
| `GET`  | `/share/{token}`          | None (public)         | Returns the scan if the token is valid, not expired, and (if protected) the correct `password` query parameter is supplied. |

## Design decisions / assumptions

- Only the scan's owner may create a share link for it (same ownership model as `PATCH`/`DELETE /scans/{id}`).
- The token is a 256-bit random value (`secrets.token_urlsafe(32)`), not a JWT — it needs to be looked up, expired, and revocable server-side, and carries no embedded data to tamper with. Only its SHA-256 hash is stored, so a database compromise (e.g. via the pre-existing SQL injection in `search_scans_by_query`, see `docs/findings.md`) doesn't hand out directly-usable share links.
- Links expire 24 hours after creation, enforced server-side on every fetch.
- `share_url` is built from the incoming request's host (`request.base_url`), not hardcoded — so it's correct regardless of how the service is actually deployed/proxied. Because that makes the response host-header-dependent, `TrustedHostMiddleware` (`app/config.py: ALLOWED_HOSTS`) rejects any request whose `Host` header isn't on an explicit allow-list, closing off Host-header spoofing of the returned URL.
- Optional password is hashed with the same bcrypt-backed helper used for user accounts. Wrong-password attempts are capped at 5, after which the link locks for 15 minutes (not permanently — a permanent lock would let anyone holding the link deny it to the intended recipient with 5 bad guesses).
- The public response schema (`SharedScanOut`) deliberately omits `owner_id` and other internal fields — data minimization for an external audience.
- Known, deliberately deferred gaps (password passed as a query parameter per this endpoint's spec, no manual revoke-before-expiry, no dedicated access audit log) are documented with reasoning in `docs/remediation-plan.md`.
