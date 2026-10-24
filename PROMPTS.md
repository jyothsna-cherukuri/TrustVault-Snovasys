# PROMPTS.md — AI-assisted development record (working draft)

This project was created with AI assistance. These entries describe actual requests and code-review decisions from the 2026-10-24 iteration. They are **not a substitute for your own ongoing log**. Before submission, add the real commit URL after each genuine change, include your own observations from running the code, and do not invent test results or history.

## Entry 1 — 2026-10-24 — Authorization: administrator content boundary

* **Prompt / request:** The owner grants a viewer access to a document. Should the administrator also be able to read it? The project must follow least privilege and the TrustVault requirements.
* **What the tool produced:** A first implementation in which `doc\_permission()` treated `admin` as an automatic content-access bypass; the document page also displayed download controls for admins.
* **What was wrong:** The role bypass meant an administrator could download confidential bytes without a document-specific grant. Hiding controls alone would not prevent a direct URL request.
* **What changed:** The revised helper explicitly denies admin users on content routes, even if a stale/legacy grant row exists. The admin page lists metadata and audit activity only, and its UI omits the download button.
* **Verification:** Automated test `test\_admin\_sees\_metadata\_but\_cannot\_download\_even\_if\_stale\_grant\_exists` was added. Run `python -m pytest -q` locally and record the actual result here.
* **Commit:** PENDING — after testing, create a real commit for this change and replace this line with its actual GitHub commit URL.

## Entry 2 — 2026-10-24 — Authorization: read vs edit vs delete

* **Prompt / request:** Check whether a user with a document grant can use the same permission to edit, delete, or grant access to other users.
* **What the tool produced:** The earlier implementation used an edit permission check for deletion and allowed admin exceptions in grant management.
* **What was wrong:** A grantee with `edit` could potentially delete a document or manage sharing, exceeding the intended grant. The owner should retain control of deletion and sharing.
* **What changed:** A `read` grant permits read/download; an `edit` grant additionally permits title/category edits; only the document owner can delete or grant/revoke access. Admin is not an exception.
* **Verification:** Added tests for read-grant edit/delete denial and edit-grantee delete/grant denial. Run the suite and record the exact output.
* **Commit:** PENDING — add the actual commit URL after the real commit.

## Entry 3 — 2026-10-24 — Audit trail integrity

* **Prompt / request:** Record allowed and denied actions and make ordinary database edits to the audit trail detectable.
* **What the tool produced:** An HMAC-SHA256 chain using a previous-event hash and a verifier on the admin audit screen.
* **What was wrong / residual risk:** A hash chain alone is not independent proof if an attacker controls the database and signing key. Concurrent append operations also need serialization.
* **What changed:** Audit appends use a SQLite `BEGIN IMMEDIATE` transaction; production configuration requires a separate audit key; the threat model explicitly records that external WORM/append-only export is unfinished.
* **Verification:** Added `test\_audit\_chain\_detects\_tampered\_event`. Run it locally and record actual output. Do not describe the chain as absolute non-repudiation.
* **Commit:** PENDING — add the actual commit URL after the real commit.

## Entry 4 — 2026-10-24 — Upload validation and private storage

* **Prompt / request:** Review upload handling for unsafe filenames, invalid extensions, oversize content, and misleading file types.
* **What the tool produced:** Extension allowlisting, byte-size limits, filename sanitization, random storage names, and basic signature checks.
* **What was wrong:** The original PNG signature check compared against escaped backslash characters instead of the actual binary PNG signature. Basic signatures also cannot replace malware scanning or deep parsing.
* **What changed:** Corrected the PNG signature check, added basic JPEG and Office-container checks, preserved random server-generated storage names, and documented the residual risk honestly.
* **Verification:** Added `test\_upload\_rejects\_disallowed\_extension\_and\_bad\_signature`. It must be run locally; passing a signature check is not a guarantee that a file is safe.
* **Commit:** PENDING — add the actual commit URL after the real commit.

## Entry 5 — 2026-10-24 — Production credentials and account lifecycle

* **Prompt / request:** Review the demo setup before deploying a stranger-accessible website; ensure public deployment does not silently seed known demo passwords.
* **What the tool produced:** The original code seeded public demo credentials whenever the database was empty and did not provide account provisioning.
* **What was wrong:** If deployed unchanged, known demo passwords could be used by anyone. The original admin user list was read-only, so safe production setup was incomplete.
* **What changed:** Local demo seeding remains a development convenience. Production requires strong independent session/audit secrets and a one-time bootstrap admin password; admins can create owner/viewer accounts and deactivate accounts, which removes their grants.
* **Verification:** Review `.env.example`, run a clean local startup, and test account creation/deactivation. Production environment variables and deployment still need to be configured by the project owner.
* **Commit:** PENDING — add the actual commit URL after the real commit.

## Reusable project instruction

“Treat authorization as a server-side security invariant. For every route, identify actor, object, action, and policy before implementation. Never trust IDs, filenames, MIME headers, role claims from the browser, or hidden controls. Add a negative test for every security rule. Do not describe a feature as complete until it has been run and verified.”

# \## Current verification status

###### 

###### \* \*\*Python syntax compilation:\*\* Reported as run by the packager before distributing the ZIP.

###### \* \*\*Flask/pytest integration suite:\*\* Ran `python -m pytest -q` locally on 2026-10-25. Result: \*\*13 passed in 9.65 seconds\*\*.

###### \* \*\*Git commit URLs:\*\* Add the actual GitHub commit URL to each entry only after verifying that the corresponding change exists in that commit. Never backdate commits or fabricate links.

###### 

