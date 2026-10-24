PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS documents (
 id INTEGER PRIMARY KEY,
 owner_id INTEGER NOT NULL REFERENCES users(id),
 title TEXT NOT NULL,
 category TEXT NOT NULL,
 original_name TEXT NOT NULL,
 stored_name TEXT UNIQUE NOT NULL,
 mime_type TEXT NOT NULL,
 size_bytes INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 created_at TEXT NOT NULL,
 deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS grants (
 id INTEGER PRIMARY KEY,
 document_id INTEGER NOT NULL REFERENCES documents(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
 granted_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL,
 UNIQUE(document_id,user_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY,
 actor_id INTEGER REFERENCES users(id),
 actor_name TEXT NOT NULL,
 action TEXT NOT NULL,
 document_id INTEGER,
 target_user TEXT,
 details TEXT NOT NULL,
 created_at TEXT NOT NULL,
 previous_hash TEXT NOT NULL,
 event_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_title ON documents(title);
CREATE INDEX IF NOT EXISTS idx_grants_user_document ON grants(user_id,document_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
