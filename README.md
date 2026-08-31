# Secure Login System

A secure authentication web application developed using Python Flask and SQLite.

This project demonstrates common web authentication and security practices including password hashing, CSRF protection, input validation, session management, SQL injection protection and optional Two-Factor Authentication.

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
- GitHub Actions continuous integration
- Responsive web interface

## Security Features

### 1. Password Security

Passwords are never stored as plain text.

The application uses bcrypt to generate a secure password hash before storing the password.

### 2. SQL Injection Protection

Database queries use parameterized SQL statements instead of directly inserting user input into SQL queries.

Example:

```python
conn.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
)
