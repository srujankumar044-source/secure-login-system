import os
import re
import sqlite3
import secrets
from functools import wraps

import bcrypt
import pyotp
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)


app = Flask(__name__)


# -----------------------------
# Application configuration
# -----------------------------

# Use an environment variable in deployment.
# A random temporary key is used when running locally.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

DATABASE = os.environ.get(
    "DATABASE_PATH",
    "database.db"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    )
)


# -----------------------------
# Security headers
# -----------------------------

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response


# -----------------------------
# Database functions
# -----------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# Input validation
# -----------------------------

def valid_username(username):
    return re.fullmatch(
        r"[A-Za-z0-9_]{3,30}",
        username
    ) is not None


def valid_email(email):
    return re.fullmatch(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ) is not None


def valid_password(password):
    return len(password) >= 8


# -----------------------------
# CSRF protection
# -----------------------------

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {
        "csrf_token": get_csrf_token()
    }


def check_csrf():
    token = request.form.get("csrf_token")

    session_token = session.get(
        "csrf_token",
        ""
    )

    return (
        token is not None
        and secrets.compare_digest(
            token,
            session_token
        )
    )


# -----------------------------
# Login required decorator
# -----------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# -----------------------------
# Home page
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html")


# -----------------------------
# Registration
# -----------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if not check_csrf():
            flash("Invalid security token.")
            return redirect(url_for("register"))

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not valid_username(username):
            flash(
                "Username must contain 3-30 letters, "
                "numbers or underscores."
            )
            return render_template("register.html")

        if not valid_email(email):
            flash("Please enter a valid email address.")
            return render_template("register.html")

        if not valid_password(password):
            flash(
                "Password must contain at least 8 characters."
            )
            return render_template("register.html")

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        conn = get_db()

        try:
            conn.execute(
                """
                INSERT INTO users
                (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            flash("Username or email already exists.")
            return render_template("register.html")

        conn.close()

        flash(
            "Registration successful. Please log in."
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# -----------------------------
# Login
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if not check_csrf():
            flash("Invalid security token.")
            return redirect(url_for("login"))

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        conn.close()

        if user and bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        ):

            session.clear()

            session["csrf_token"] = secrets.token_urlsafe(32)

            if user["two_factor_enabled"]:

                session["pending_user_id"] = user["id"]

                return redirect(
                    url_for("verify_2fa")
                )

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful.")

            return redirect(
                url_for("dashboard")
            )

        flash("Invalid username or password.")

    return render_template("login.html")


# -----------------------------
# 2FA verification
# -----------------------------

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():

    pending_user_id = session.get(
        "pending_user_id"
    )

    if not pending_user_id:
        return redirect(url_for("login"))

    if request.method == "POST":

        if not check_csrf():
            flash("Invalid security token.")
            return redirect(url_for("login"))

        otp = request.form.get(
            "otp",
            ""
        ).strip()

        if not otp.isdigit() or len(otp) != 6:
            flash(
                "Enter a valid 6-digit verification code."
            )
            return render_template(
                "verify_2fa.html"
            )

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (pending_user_id,)
        ).fetchone()

        conn.close()

        if user and user["two_factor_secret"]:

            totp = pyotp.TOTP(
                user["two_factor_secret"]
            )

            if totp.verify(otp):

                session.clear()

                session["csrf_token"] = (
                    secrets.token_urlsafe(32)
                )

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                flash(
                    "Two-factor authentication successful."
                )

                return redirect(
                    url_for("dashboard")
                )

        flash("Invalid verification code.")

    return render_template(
        "verify_2fa.html"
    )


# -----------------------------
# Dashboard
# -----------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    user = conn.execute(
        """
        SELECT username, email, two_factor_enabled
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if user is None:
        session.clear()
        flash("User account not found.")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        user=user
    )


# -----------------------------
# Enable 2FA
# -----------------------------

@app.route("/enable-2fa", methods=["POST"])
@login_required
def enable_2fa():

    if not check_csrf():
        flash("Invalid security token.")
        return redirect(url_for("dashboard"))

    secret = pyotp.random_base32()

    conn = get_db()

    conn.execute(
        """
        UPDATE users
        SET two_factor_enabled = 1,
            two_factor_secret = ?
        WHERE id = ?
        """,
        (
            secret,
            session["user_id"]
        )
    )

    conn.commit()
    conn.close()

    session["new_2fa_secret"] = secret

    flash(
        "2FA enabled. Save your secret key "
        "in an authenticator app."
    )

    return redirect(
        url_for("dashboard")
    )


# -----------------------------
# Disable 2FA
# -----------------------------

@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():

    if not check_csrf():
        flash("Invalid security token.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    conn.execute(
        """
        UPDATE users
        SET two_factor_enabled = 0,
            two_factor_secret = NULL
        WHERE id = ?
        """,
        (session["user_id"],)
    )

    conn.commit()
    conn.close()

    flash(
        "Two-factor authentication disabled."
    )

    return redirect(
        url_for("dashboard")
    )


# -----------------------------
# Logout
# -----------------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    if not check_csrf():
        flash("Invalid security token.")
        return redirect(url_for("dashboard"))

    session.clear()

    flash("You have been logged out.")

    return redirect(
        url_for("index")
    )


# -----------------------------
# Initialize database
# -----------------------------

init_db()


# -----------------------------
# Application entry point
# -----------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=int(
            os.environ.get("PORT", 5000)
        ),
        debug=(
            os.environ.get("FLASK_DEBUG", "0") == "1"
        )
          )
