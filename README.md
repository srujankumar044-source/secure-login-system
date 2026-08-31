# Secure Login System

A secure authentication web application developed using Python Flask and SQLite.

The project demonstrates common web authentication and security practices including password hashing, CSRF protection, input validation, session management, SQL injection protection and optional Two-Factor Authentication.

## Project Objective

The objective of this project is to develop a secure login system that protects user accounts from common web application security threats.

## Key Features

- User registration
- User login and logout
- Secure password hashing using bcrypt
- Input validation
- SQL injection protection using parameterized queries
- CSRF protection
- Secure session management
- Protected dashboard
- Optional Two-Factor Authentication (2FA)
- SQLite database
- Security response headers
- Automated tests using pytest
- Responsive web interface

## Security Features

### Password Security

Passwords are never stored as plain text.

The application uses bcrypt to generate a secure password hash before storing the password.

### SQL Injection Protection

Database queries use parameterized SQL statements instead of directly inserting user input into SQL queries.

### CSRF Protection

POST requests are protected using a session-based CSRF token.

### Session Security

The application uses:

- HttpOnly session cookies
- SameSite=Lax
- Configurable Secure cookies
- Session clearing after authentication changes

### Input Validation

The application validates:

- Username format
- Email format
- Minimum password length
- Two-factor authentication codes

### Two-Factor Authentication

Users can optionally enable TOTP-based two-factor authentication using an authenticator application.

## Technologies Used

- Python
- Flask
- SQLite
- bcrypt
- PyOTP
- HTML5
- CSS3
- pytest
- GitHub Actions

## Project Structure

```text
secure-login-system/
│
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   └── verify_2fa.html
│
├── static/
│   └── style.css
│
├── tests/
│   └── test_app.py
│
└── .github/
    └── workflows/
        └── tests.yml
