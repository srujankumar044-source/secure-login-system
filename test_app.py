import os

import pytest

os.environ["TESTING"] = "1"

import app


@pytest.fixture
def client(tmp_path, monkeypatch):

    test_database = tmp_path / "test.db"

    monkeypatch.setattr(
        app,
        "DATABASE",
        str(test_database)
    )

    app.init_db()

    app.app.config["TESTING"] = True

    with app.app.test_client() as client:
        yield client


def get_csrf(client):

    response = client.get("/register")

    with client.session_transaction() as session:
        return session["csrf_token"]


def test_home_page(client):

    response = client.get("/")

    assert response.status_code == 200


def test_user_registration(client):

    token = get_csrf(client)

    response = client.post(
        "/register",
        data={
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
            "csrf_token": token
        },
        follow_redirects=True
    )

    assert response.status_code == 200


def test_login(client):

    token = get_csrf(client)

    client.post(
        "/register",
        data={
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
            "csrf_token": token
        }
    )

    token = get_csrf(client)

    response = client.post(
        "/login",
        data={
            "username": "testuser",
            "password": "password123",
            "csrf_token": token
        },
        follow_redirects=True
    )

    assert response.status_code == 200


def test_invalid_login(client):

    token = get_csrf(client)

    response = client.post(
        "/login",
        data={
            "username": "wronguser",
            "password": "wrongpassword",
            "csrf_token": token
        }
    )

    assert b"Invalid username or password" in response.data
