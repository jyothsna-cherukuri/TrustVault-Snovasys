# TrustVault — design write-up (personalize this in your own words before submission)

## What the prototype does
TrustVault is a Flask web application with SQLite metadata and private file storage. It provides authentication, admin/owner/viewer roles, per-document read/edit grants, upload validation, search, sharing and revocation, account administration, and an HMAC-linked audit trail.

## Permission model
The server makes authorization decisions on every sensitive request. A document owner can access their own file. Another non-admin user needs a current explicit grant for that exact document. A `read` grant allows downloading; an `edit` grant also permits title/category edits. Only the owner can delete a document or grant/revoke access. The administrator can manage accounts, view document metadata, and inspect audit events, but **admin status does not grant access to file contents**. The content authorization helper explicitly denies admins even if an old/stale grant row exists. Revocation removes the grant from SQLite so later requests are denied; it cannot recall bytes a recipient already downloaded.

## Audit design
Each event stores a previous-event hash and an HMAC-SHA256 over canonical event fields. Appends use a SQLite immediate transaction to serialize the chain. The admin view verifies the chain and displays denied attempts. This detects ordinary database row alteration when the key remains trusted; it is not absolute non-repudiation. A production design should export events to separately controlled append-only/WORM storage and protect signing keys independently.

## How AI was used
AI generated and reviewed parts of the starter code, tests, and documentation. Complete `PROMPTS.md` with your actual interactions, what you checked, what was wrong, what you changed, actual test output, and real commit links. Do not claim work or tests you did not personally verify.

## Deliberately not built / unfinished
No MFA, rate limiting, malware scanner, external WORM audit sink, document version history, retention/restore UI, password reset, enterprise SSO, or multi-region storage. Basic file signatures are not malware scanning. Test results and a real deployment URL must be added after you run and deploy the project yourself.
