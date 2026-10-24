import re
import pytest


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    storage = tmp_path / "storage"
    monkeypatch.setenv("TRUSTVAULT_DB", str(db))
    monkeypatch.setenv("TRUSTVAULT_STORAGE", str(storage))
    import app as module
    module.DB_PATH = db
    module.STORAGE = storage
    module.STORAGE.mkdir(parents=True, exist_ok=True)
    module.SECRET_KEY = "test-session-secret"
    module.AUDIT_KEY = "test-independent-audit-key"
    module.app.config.update(TESTING=True, SECRET_KEY="test-session-secret", WTF_CSRF_ENABLED=False)
    module.init_db()
    yield module.app
    try:
        db.unlink()
    except FileNotFoundError:
        pass


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_token(client):
    response = client.get("/login")
    match = re.search(rb'name="csrf_token" value="([^"]*)"', response.data)
    assert match, "login form must include a CSRF token"
    return match.group(1).decode()


def signin(client, username, password):
    token = csrf_token(client)
    return client.post("/login", data={"username": username, "password": password,
                                      "csrf_token": token}, follow_redirects=True)
