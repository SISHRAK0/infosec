import pytest

from app import app, init_db


@pytest.fixture
def client(tmp_path):
    app.config["DATABASE"] = str(tmp_path / "test.db")
    init_db()
    return app.test_client()


def register(client, username="alice", password="password123"):
    return client.post("/auth/register", json={"username": username, "password": password})


def login(client, username="alice", password="password123"):
    return client.post("/auth/login", json={"username": username, "password": password})


def test_login_and_get_data(client):
    assert register(client).status_code == 201
    token = login(client).get_json()["access_token"]

    response = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json() == {"users": [{"id": 1, "username": "alice"}]}


def test_data_without_token_is_forbidden(client):
    assert client.get("/api/data").status_code == 401
    assert client.get("/api/data", headers={"Authorization": "Bearer fake"}).status_code == 401


def test_wrong_password(client):
    register(client)
    assert login(client, password="wrong-password").status_code == 401


def test_sql_injection_in_login(client):
    register(client)
    assert login(client, username="alice' --", password="anything").status_code == 401
    assert login(client, username="' OR '1'='1", password="' OR '1'='1").status_code == 401


def test_username_is_escaped(client):
    register(client, username="<script>alert(1)</script>")
    token = login(client, username="<script>alert(1)</script>").get_json()["access_token"]

    body = client.get("/api/data", headers={"Authorization": f"Bearer {token}"}).get_data(as_text=True)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
