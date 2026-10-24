# Five-minute demo recording plan

Record your own screen and voice. This is a plan, not evidence that a feature passed. Only show steps you actually verified.

**0:00–0:30 — Problem and roles**
- Explain per-document access and the need for a trustworthy audit trail.
- State the policy: admin can see metadata/audit but not confidential file bytes; owners control their documents; viewers need explicit grants.

**0:30–1:20 — Owner upload and search**
- Sign in as local `owner`.
- Upload a small sample `.txt` file with title/category.
- Search by title, owner/category, and date if useful.

**1:20–2:10 — Grant and revoke**
- Open Manage sharing; grant `viewer` read permission.
- Use a second browser/client session as `viewer` and download the document.
- Revoke from owner session and retry from the viewer session. Show the denied request.

**2:10–3:00 — Negative authorization and admin boundary**
- Sign in as `otherowner` and try the direct download URL for a document they were not granted.
- Sign in as `admin`: show metadata and audit access, then try a direct document download and show denial.
- Explain that the server checks every request; hiding a button alone is not security.

**3:00–4:00 — Audit evidence**
- Show upload, download, grant, revoke and denied-attempt events.
- Show the HMAC chain status. Explain the limitation: no independent WORM log export is implemented.

**4:00–5:00 — Tests and engineering**
- Show `THREATS.md`, `API.md`, `PROMPTS.md` and the real output from `python -m pytest -q`.
- State actual deployment URL, what is unfinished, and which AI-generated suggestion you caught and corrected. Never present a test as passed if you have not run it.
