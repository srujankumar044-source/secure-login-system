import os
import sys

import pytest
import pyotp

# Add the project root directory to Python's import path.
sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )
)

os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key"

import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a test client with a temporary database."""

    test_database = tmp_path / "test.db"

    monkeypatch.setattr(
        app,
        "DATABASE",
        str(test_database)
    )

    app.init_db()

    app.app.config.update(
        TESTING=True,
        SESSION_COOKIE_SECURE=False
    )

    with app.app.test_client() as client:
        yield client


def get_csrf(client, page="/register"):
    """Get the CSRF token from the current session."""

    response = client.get(page)

    assert response.status_code == 200

    with client.session_transaction() as session:
        return session["csrf_token"]


def register_user(
    client,
    username="testuser",
    email="test@example.com",
    password="password123"
):
    """Register a test user."""

    token = get_csrf(client)

    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "csrf_token": token
        },
        follow_redirects=True
    )


def login_user(
    client,
    username="testuser",
    password="password123"
):
    """Log in a test user."""

    token = get_csrf(
        client,
        "/login"
    )

    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": token
        },
        follow_redirects=True
    )


def test_home_page(client):
    response = client.get("/")

    assert response.status_code == 200


def test_user_registration(client):
    response = register_user(client)

    assert response.status_code == 200
    assert b"Registration successful" in response.data


def test_duplicate_registration(client):
    register_user(client)

    response = register_user(client)

    assert response.status_code == 200
    assert b"already exists" in response.data


def test_invalid_username(client):
    response = register_user(
        client,
        username="ab"
    )

    assert b"Username must contain" in response.data


def test_invalid_email(client):
    response = register_user(
        client,
        email="invalid-email"
    )

    assert b"valid email" in response.data


def test_short_password(client):
    response = register_user(
        client,
        password="123"
    )

    assert b"at least 8 characters" in response.data


def test_login(client):
    register_user(client)

    response = login_user(client)

    assert response.status_code == 200
    assert b"Welcome" in response.data


def test_invalid_login(client):
    response = login_user(
        client,
        username="wronguser",
        password="wrongpassword"
    )

    assert b"Invalid username or password" in response.data


def test_dashboard_requires_login(client):
    response = client.get(
        "/dashboard",
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Please log in first" in response.data


def test_csrf_protection(client):
    response = client.post(
        "/login",
        data={
            "username": "testuser",
            "password": "password123"
        }
    )

    assert response.status_code == 302


def test_logout(client):
    register_user(client)
    login_user(client)

    token = get_csrf(
        client,
        "/dashboard"
    )

    response = client.post(
        "/logout",
        data={
            "csrf_token": token
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"logged out" in response.data


def test_2fa_login(client):
    register_user(client)

    secret = pyotp.random_base32()

    conn = app.get_db()

    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("testuser",)
    ).fetchone()

    conn.execute(
        """
        UPDATE users
        SET two_factor_enabled = 1,
            two_factor_secret = ?
        WHERE id = ?
        """,
        (
            secret,
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    response = login_user(client)

    assert response.status_code == 200
    assert b"verification" in response.data.lower()

    otp = pyotp.TOTP(secret).now()

    token = get_csrf(
        client,
        "/verify-2fa"
    )

    response = client.post(
        "/verify-2fa",
        data={
            "otp": otp,
            "csrf_token": token
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Welcome" in response.data


def test_invalid_2fa_code(client):
    register_user(client)

    secret = pyotp.random_base32()

    conn = app.get_db()

    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("testuser",)
    ).fetchone()

    conn.execute(
        """
        UPDATE users
        SET two_factor_enabled = 1,
            two_factor_secret = ?
        WHERE id = ?
        """,
        (
            secret,
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    login_user(client)

    token = get_csrf(
        client,
        "/verify-2fa"
    )

    response = client.post(
        "/verify-2fa",
        data={
            "otp": "000000",
            "csrf_token": token
        }
    )

    assert b"Invalid verification code" in response.data
