# Secure Login System

A simple secure login web application developed using Python Flask and SQLite.

## Project Description

This project demonstrates the implementation of a secure authentication system.

The application allows users to register, log in, manage sessions, and optionally enable two-factor authentication.

## Features

- User registration
- User login
- Secure password hashing using bcrypt
- Basic input validation
- SQL injection protection
- Secure session management
- Logout functionality
- CSRF protection
- Optional Two-Factor Authentication (2FA)
- SQLite database
- Basic automated tests
- Responsive web interface

## Technologies Used

- Python
- Flask
- SQLite
- bcrypt
- PyOTP
- HTML
- CSS
- pytest

## Project Structure

```text
secure-login-system/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
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
└── tests/
    └── test_app.py
