import io
import re

from tests.conftest import signin


def csrf(client):
    with client.session_transaction() as session:
        return session.get("csrf_token", "")


def upload(client, title="Secret contract", filename="contract.txt", content=b"Confidential test document"):
    return client.post("/documents/upload", data={
        "csrf_token": csrf(client), "title": title, "category": "Legal",
        "file": (io.BytesIO(content), filename)
    }, content_type="multipart/form-data", follow_redirects=True)


def document_id(app):
    from app import connect_db
    con = connect_db()
    row = con.execute("SELECT id FROM documents ORDER BY id LIMIT 1").fetchone()
    con.close()
    return row["id"]


def user_id(username):
    from app import connect_db
    con = connect_db()
    row = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    return row["id"]


def test_owner_can_upload_and_download_own_document(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    response = upload(client)
    assert response.status_code == 200
    doc_id = document_id(app)
    download = client.get(f"/documents/{doc_id}/download")
    assert download.status_code == 200
    assert download.data == b"Confidential test document"


def test_ungranted_user_cannot_download_another_owners_document(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    doc_id = document_id(app)
    signin(client, "otherowner", "OtherOwner!2026")
    assert client.get(f"/documents/{doc_id}/download").status_code == 403


def test_viewer_cannot_upload(client):
    signin(client, "viewer", "ViewerDemo!2026")
    response = client.post("/documents/upload", data={"csrf_token": csrf(client), "title": "x", "category": "x"})
    assert response.status_code == 403


def test_admin_sees_metadata_but_cannot_download_even_if_stale_grant_exists(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client, title="Admin must not read this")
    doc_id = document_id(app)
    from app import connect_db
    con = connect_db()
    admin_id = con.execute("SELECT id FROM users WHERE username='admin'").fetchone()["id"]
    owner_id = con.execute("SELECT id FROM users WHERE username='owner'").fetchone()["id"]
    # Simulate a legacy/erroneous grant; admin content access must still be denied.
    con.execute("INSERT INTO grants(document_id,user_id,permission,granted_by,created_at) VALUES(?,?,?,?,?)",
                (doc_id, admin_id, "read", owner_id, "2026-10-24T00:00:00+00:00"))
    con.commit(); con.close()
    signin(client, "admin", "AdminDemo!2026")
    page = client.get("/documents")
    assert b"Admin must not read this" in page.data
    assert b"Download" not in page.data
    assert client.get(f"/documents/{doc_id}/download").status_code == 403


def test_admin_cannot_upload_or_change_document_metadata(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    doc_id = document_id(app)
    signin(client, "admin", "AdminDemo!2026")
    upload_response = client.post("/documents/upload", data={"csrf_token": csrf(client), "title": "x", "category": "x"})
    assert upload_response.status_code == 403
    edit_response = client.post(f"/documents/{doc_id}/edit", data={"csrf_token": csrf(client), "title": "Changed", "category": "Legal"})
    assert edit_response.status_code == 403


def test_granted_viewer_can_download_and_revocation_immediately_blocks_new_requests(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    doc_id = document_id(app)
    client.post(f"/documents/{doc_id}/grant", data={"csrf_token": csrf(client),
                "user_id": user_id("viewer"), "permission": "read"}, follow_redirects=True)
    viewer_client = client.application.test_client()
    signin(viewer_client, "viewer", "ViewerDemo!2026")
    assert viewer_client.get(f"/documents/{doc_id}/download").status_code == 200
    client.post(f"/documents/{doc_id}/revoke", data={"csrf_token": csrf(client),
                "user_id": user_id("viewer")}, follow_redirects=True)
    assert viewer_client.get(f"/documents/{doc_id}/download").status_code == 403


def test_read_grant_cannot_edit_or_delete(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    doc_id = document_id(app)
    client.post(f"/documents/{doc_id}/grant", data={"csrf_token": csrf(client),
                "user_id": user_id("viewer"), "permission": "read"}, follow_redirects=True)
    viewer_client = client.application.test_client()
    signin(viewer_client, "viewer", "ViewerDemo!2026")
    assert viewer_client.post(f"/documents/{doc_id}/edit", data={"csrf_token": csrf(viewer_client),
                "title": "Changed", "category": "Legal"}).status_code == 403
    assert viewer_client.post(f"/documents/{doc_id}/delete", data={"csrf_token": csrf(viewer_client)}).status_code == 403


def test_edit_grant_can_edit_metadata_but_cannot_delete_or_manage_grants(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    doc_id = document_id(app)
    client.post(f"/documents/{doc_id}/grant", data={"csrf_token": csrf(client),
                "user_id": user_id("viewer"), "permission": "edit"}, follow_redirects=True)
    viewer_client = client.application.test_client()
    signin(viewer_client, "viewer", "ViewerDemo!2026")
    assert viewer_client.post(f"/documents/{doc_id}/edit", data={"csrf_token": csrf(viewer_client),
                "title": "Updated by editor", "category": "Legal"}).status_code == 302
    assert viewer_client.post(f"/documents/{doc_id}/delete", data={"csrf_token": csrf(viewer_client)}).status_code == 403
    assert viewer_client.post(f"/documents/{doc_id}/grant", data={"csrf_token": csrf(viewer_client),
                "user_id": user_id("otherowner"), "permission": "read"}).status_code == 403


def test_denied_access_is_audited(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    doc_id = document_id(app)
    signin(client, "otherowner", "OtherOwner!2026")
    assert client.get(f"/documents/{doc_id}/download").status_code == 403
    from app import connect_db
    con = connect_db()
    row = con.execute("SELECT action FROM audit_events WHERE action='DOCUMENT_ACCESS_DENIED'").fetchone()
    con.close()
    assert row is not None


def test_csrf_protects_mutating_routes(client):
    signin(client, "owner", "OwnerDemo!2026")
    response = client.post("/documents/upload", data={"title": "No token", "category": "test"})
    assert response.status_code == 400


def test_upload_rejects_disallowed_extension_and_bad_signature(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    response = upload(client, filename="payload.exe", content=b"not executable")
    assert b"File type not allowed" in response.data
    response = upload(client, filename="fake.pdf", content=b"not a pdf")
    assert b"File content does not match" in response.data
    from app import connect_db
    con = connect_db()
    assert con.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0
    con.close()


def test_audit_chain_detects_tampered_event(client, app):
    signin(client, "owner", "OwnerDemo!2026")
    upload(client)
    from app import connect_db, verify_audit_chain
    assert verify_audit_chain() is True
    con = connect_db()
    con.execute("UPDATE audit_events SET details='{}' WHERE action='UPLOAD'")
    con.commit(); con.close()
    assert verify_audit_chain() is False


def test_inactive_user_is_denied_after_deactivation(client, app):
    signin(client, "admin", "AdminDemo!2026")
    target = user_id("viewer")
    response = client.post(f"/admin/users/{target}/deactivate", data={"csrf_token": csrf(client)}, follow_redirects=True)
    assert response.status_code == 200
    viewer_client = client.application.test_client()
    login_page = viewer_client.get("/login")
    token = re.search(rb'name="csrf_token" value="([^"]*)"', login_page.data).group(1).decode()
    login_response = viewer_client.post("/login", data={"username": "viewer", "password": "ViewerDemo!2026", "csrf_token": token}, follow_redirects=True)
    assert b"Invalid username or password" in login_response.data
