# TrustVault route and permission reference

All state-changing routes require a session CSRF token. All authenticated routes re-check that the account is active. Content routes authorize against current database grants on each request; the UI is not a security boundary.

| Method | Route | Authentication / authorization | Notes |
|---|---|---|---|
| GET | `/` | Public | Redirects to login or documents |
| GET, POST | `/login` | Public; CSRF on POST | Generic login failure response; failure is audited |
| POST | `/logout` | Any authenticated user + CSRF | Clears session |
| GET | `/documents` | Authenticated | Owner/viewer sees owned or explicitly shared metadata; admin sees metadata only |
| POST | `/documents/upload` | Owner only + CSRF | Extension, size, filename and basic signature validation |
| GET | `/documents/<id>/download` | Owner or active named `read`/`edit` grant; admin explicitly denied | Private storage; logs successful and denied access |
| POST | `/documents/<id>/edit` | Owner or active named `edit` grant + CSRF; admin denied | Changes title/category only |
| POST | `/documents/<id>/delete` | Document owner only + CSRF | Soft delete and remove grants |
| POST | `/documents/<id>/grant` | Document owner only + CSRF | Grant named active non-admin user `read` or `edit` |
| POST | `/documents/<id>/revoke` | Document owner only + CSRF | Deletes current grant; later requests fail |
| GET | `/documents/<id>/grants` | Document owner only | JSON list of grants; not exposed to unrelated users |
| GET | `/admin/audit` | Admin only | Latest 500 events and full-chain integrity result |
| GET | `/admin/users` | Admin only | Account list and account provisioning form |
| POST | `/admin/users/create` | Admin only + CSRF | Creates owner/viewer; minimum 12-character password |
| POST | `/admin/users/<id>/deactivate` | Admin only + CSRF | Deactivates account, removes grants; protects current/last admin |
| GET | `/health` | Public | Basic health check only |

## Important policy choices

- Admin can inspect metadata, user accounts and audit events, but **cannot download or edit document content**. The server explicitly denies admins on content routes even if a stale grant row exists.
- A read grant permits downloading only. An edit grant permits download plus title/category changes. Only the owner can delete or manage grants.
- Revocation is immediate for new HTTP requests. It cannot erase copies downloaded earlier.
- Audit events use HMAC-SHA256 over a previous-hash chain. This detects ordinary row edits/deletions as long as the signing key is trusted; it is not equivalent to an independent WORM log.
