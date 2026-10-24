# TrustVault threat model

Last reviewed: 2026-10-24. This is a working model. Re-run tests and verify the deployed system before submission.

## Assets
- Confidential document bytes and metadata.
- Per-document grants and owner identity.
- Authentication sessions and account credentials.
- Audit evidence for successful and denied activity.
- Integrity of the application, database, storage directory and signing keys.

## Trust boundaries
Browser → Flask routes; Flask → SQLite; Flask → private file storage; app process → environment secrets; deployment operator → persistent disk and backups.

## Threats, controls, and residual risk

| Threat | Control in this build | Verification / residual risk |
|---|---|---|
| Viewer guesses another document ID | Every download/edit route checks the current owner/grant in the database | `test_ungranted_user_cannot_download_another_owners_document`; continue testing all routes |
| Admin role is misused to read confidential bytes | Admin can see metadata/audit only; content authorization explicitly denies admin, even if a stale grant row exists | `test_admin_sees_metadata_but_cannot_download_even_if_stale_grant_exists`; metadata itself is still visible to admins by design |
| Grant is revoked but old URL still works | No public/static file URL or bearer download token; each request checks current grant state | `test_granted_viewer_can_download_and_revocation_immediately_blocks_new_requests`; previously downloaded copies cannot be recalled |
| Read grant is used to edit/delete | Edit requires `edit`; deletion and grant management require the document owner | `test_read_grant_cannot_edit_or_delete` and `test_edit_grant_can_edit_metadata_but_cannot_delete_or_manage_grants` |
| Unauthorized edit/delete/grant/revoke | Route-level policy checks run on server, independently of hidden buttons | Tests cover several negative paths; add broader route fuzzing before production |
| Cross-site request forgery | Random session CSRF token required for all POST/PUT/PATCH/DELETE requests; SameSite=Lax cookie | `test_csrf_protects_mutating_routes`; still validate deployment/proxy behavior |
| SQL injection in search/forms | SQL values are parameterized; dynamic SQL fragments are fixed code-controlled predicates | Input fuzzing and deeper review still recommended |
| Path traversal via filename | `secure_filename`, random storage name, DB lookup and storage outside `static/` | Test unusual filenames; ensure deployment does not serve storage directory |
| Malicious/oversized upload | Extension allowlist, size cap, basic signatures for PDF/PNG/JPEG/Office containers, random name | `test_upload_rejects_disallowed_extension_and_bad_signature`; not antivirus or deep parsing, and CSV/TXT are not content-scanned |
| Audit row edited/deleted | HMAC-SHA256 hash chain includes previous hash and event fields; audit append is serialized with SQLite `BEGIN IMMEDIATE` | `test_audit_chain_detects_tampered_event`; a compromised app/key or coordinated DB+key access can forge history |
| Audit history is quietly rewritten by hosting operator | Audit key is configured separately from DB; chain verifies integrity | No independent WORM/remote audit sink or external timestamping; accepted prototype limitation |
| Password guessing/credential stuffing | Werkzeug password hashing and generic login failure | No rate limiting, MFA or breached-password check; accepted prototype gap |
| Session theft | HttpOnly, SameSite=Lax, session rotation on login, short permanent lifetime; Secure cookie in production | HTTPS and `COOKIE_SECURE=1` required; deployment configuration must be verified |
| XSS via title/category/username | Jinja autoescaping, restrictive CSP, no user-controlled HTML rendering | Test payloads; avoid marking content safe |
| Inactive user keeps access | Current user lookup checks `active=1` every request; deactivation removes grants | No reactivation workflow; deactivated account needs operator/admin decision |
| Admin account lockout | UI prevents deactivating current admin or last active admin | Test multi-admin scenarios if used beyond a demo |
| File survives soft delete | Soft delete removes active listing and grants; content routes reject tombstoned records | Bytes remain on disk for possible recovery; physical purge/retention workflow is not implemented |
| Lost data after redeploy | README requires persistent storage for DB and files | Free-host disk behavior and SQLite concurrency depend on provider; verify before judging |

## Permission model

- `admin`: account administration, document metadata listing and audit trail. **No file-content access by role alone.**
- `owner`: upload, edit metadata, delete owned documents, grant/revoke access to named active non-admin users.
- `viewer`: read/download only when an explicit current grant exists.
- `edit` grant: read/download plus title/category edit; it does not grant deletion or sharing authority.

## Explicitly accepted prototype gaps

No malware scanning, MFA, rate limiting, password reset, document versioning, retention/restore UI, external WORM audit sink, enterprise SSO, or high-availability storage. HMAC chaining is tamper-evident, not absolute non-repudiation. SQLite is intended for a small single-instance demo. Never upload real confidential documents or deploy demo passwords publicly.

## Security verification checklist

- [ ] Run `python -m pytest -q` and record exact output.
- [ ] Verify owner can upload and access own document.
- [ ] Verify ungranted user and admin cannot download content by direct URL.
- [ ] Verify read grant cannot edit/delete; edit grant cannot delete or grant access.
- [ ] Revoke in owner session and retry from a second viewer session.
- [ ] Verify audit chain turns invalid after a controlled test tamper.
- [ ] Verify storage is not publicly served and production cookies are Secure over HTTPS.
- [ ] Confirm production uses separate strong secrets and no demo seed accounts.
