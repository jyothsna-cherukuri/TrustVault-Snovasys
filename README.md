# TrustVault — secure document sharing with a tamper-evident audit trail

TrustVault is an educational Flask + SQLite prototype for per-document access control. The server checks permissions on every content request; files are stored under random names outside the public static directory; new requests are denied immediately after a grant is revoked; and audit events are chained with HMAC-SHA256.

> **Honest scope:** This is a hackathon prototype, not a certified production document vault. It does not include malware scanning, MFA, rate limiting, external WORM audit storage, document versioning, or disaster recovery. Do not upload real confidential files. Review `THREATS.md` and run the tests before deployment.

## Roles and security model

- **Administrator:** can view user accounts, create/deactivate owner and viewer accounts, see document metadata, and inspect/verify the audit trail. **Admin status does not grant access to file contents.** Content routes explicitly deny admin users, even if a stale grant exists.
- **Owner:** can upload documents; manage metadata and delete only documents they own; grant or revoke `read` / `edit` permissions for named active non-admin users.
- **Viewer:** can read/download a document only when an owner has granted access. An `edit` grant also permits metadata edits, but never lets the grantee delete the document or manage its grants.
- **Edit grantee:** can edit title/category for the explicitly shared document. Only its owner can delete it or change grants.

Admin can see metadata such as title, category, filename, owner and size in the admin listing. That is deliberately separate from file content. The audit view can show event metadata, not file bytes.

## Run locally on Windows

Python 3.11+ is recommended (Python 3.13 should work with a compatible Flask release).

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:8000`.

### Local demo accounts

In development mode, an empty database is seeded with these accounts by default:

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `AdminDemo!2026` |
| Owner | `owner` | `OwnerDemo!2026` |
| Viewer | `viewer` | `ViewerDemo!2026` |
| Second owner (isolation test) | `otherowner` | `OtherOwner!2026` |

These are public demo credentials for local use only. Never deploy a public instance with these credentials enabled. If the database already has users, the seed step does not overwrite them.

## Automated tests

```powershell
python -m pytest -q
```

The tests are designed to cover ownership isolation, admin content denial, explicit grants, immediate revocation, edit-vs-delete boundaries, CSRF, upload validation, denied-attempt auditing, and audit-chain tampering. **Record the actual output you get; do not claim tests passed until you have run them.**

## Production deployment checklist (Render or another WSGI host)

1. Create a private repository while developing; follow the event organizer's instructions about when to make it public. Do not expose the repository before the event if the rules prohibit it.
2. Set `TRUSTVAULT_ENV=production`.
3. Set `TRUSTVAULT_SECRET_KEY` to a random secret of at least 32 characters and `TRUSTVAULT_AUDIT_KEY` to a different random secret of at least 32 characters. Keep both out of Git and separate from the database backup.
4. On first boot only, set `TRUSTVAULT_BOOTSTRAP_ADMIN_USERNAME` and `TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD` (at least 16 characters). They are used only if the database contains no users. Create owner/viewer accounts in the admin UI after login, then remove the bootstrap password from the deployment environment if the host permits.
5. Set `COOKIE_SECURE=1`, use HTTPS, and configure a persistent disk for both SQLite and uploaded files. Example: `TRUSTVAULT_DB=/var/data/trustvault.db` and `TRUSTVAULT_STORAGE=/var/data/trustvault-files`.
6. Start command: `python app.py`. Keep a single app instance for SQLite unless you migrate to a database designed for concurrent multi-instance writes.
7. Open the deployed URL in an incognito window and run the negative authorization tests against that deployment before submitting.

Never commit `.env`, database files, or uploaded documents. Do not put real passwords in `PROMPTS.md`, README, or screenshots. A live URL is not created by this ZIP; you must deploy it from your own account and verify it.

## Upload validation

Allowed extensions: PDF, TXT, CSV, PNG, JPG/JPEG, DOCX, XLSX. Default maximum is 5 MiB. Names are sanitized; storage names are random; basic signatures are checked for PDF/PNG/JPEG/Office ZIP containers. This is **not** antivirus, deep file parsing, or a guarantee that a file is safe.

## Key files

- `app.py` — routes, role checks, per-document authorization, uploads, and audit-chain logic.
- `tests/` — automated negative and positive security checks.
- `THREATS.md` — threat model and residual risks.
- `PROMPTS.md` — AI-use log template; complete it honestly while working and add actual commit links.
- `API.md` — endpoint-by-endpoint permissions.
- `schema.sql` — reference schema.
- `WRITEUP.md` / `DEMO_SCRIPT.md` — starter material; personalize it and state what is unfinished.

## Before hand-in

- Build understanding of the authorization helper and explain why removing the check breaks access control.
- Run tests and record the exact result.
- Add real, incremental commits as you genuinely review, test, and improve the code. Do not backdate commits or fabricate history.
- Complete at least five real dated `PROMPTS.md` entries, including at least two on authorization/access control/audit. Include what was wrong, what you changed, actual test evidence, and actual commit URLs. No commit links are fabricated in this starter.
- Record your own five-minute demo and only show features that work.
- The event rules say AI use is allowed but require an individual assessment; you must understand, review, and be able to explain every submitted part.
