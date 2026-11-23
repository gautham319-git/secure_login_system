# Secure Login System

A secure login web app built with Node.js and Express. It demonstrates the core defences every login system needs: hashed passwords, input validation, SQL injection protection, session management and optional two-factor authentication.

## Features

| Requirement | How it is implemented |
|---|---|
| Registration and login with hashed passwords | `bcrypt` with 12 salt rounds. Plain-text passwords are never stored or logged. |
| Input validation | `Joi` schemas for username, email and password strength (min 8 chars, upper, lower, number, symbol). Request bodies are limited to 10 KB. |
| SQL injection protection | All queries use parameterized prepared statements (`WHERE username = ?`) with SQLite (`better-sqlite3`). |
| Session management with logout | `express-session` with `httpOnly`, `SameSite=Strict` (and `Secure` in production) cookies, a 30-minute idle timeout, session ID regeneration on login, and a logout that destroys the server-side session. |
| Optional 2FA | TOTP (Google Authenticator / Authy compatible) using `speakeasy` and a QR code. Can be enabled or disabled from the dashboard. |

### Extra hardening

- `helmet` sets security headers (CSP, HSTS, X-Content-Type-Options, frame protection).
- `express-rate-limit`: 100 requests per 15 minutes per IP overall, and only 5 failed logins per 15 minutes.
- CSRF token on every POST form.
- All HTML output is escaped to prevent XSS.
- Same error message for wrong username and wrong password, with equalised timing, so accounts cannot be enumerated.
- Secrets are loaded from environment variables (`.env`, which is git-ignored).
- `winston` logs security events (failed logins, 2FA, logouts) and hides stack traces from users in production.

## Setup

```bash
npm install
cp .env.example .env
# generate a secret and paste it into .env as SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
npm start
```

Open http://localhost:3000

Check dependencies for known vulnerabilities with `npm audit`.

## Project structure

```
server.js        Express app (routes, validation, auth, 2FA, logging)
package.json     Dependencies and scripts
.env.example     Template for environment variables
.gitignore       Keeps .env, users.db, logs and node_modules out of git
```

## Testing it

1. **Register** with a weak password such as `abc`. It is rejected with a validation message.
2. **Register** with a strong password, then open `users.db` and check that `password_hash` starts with `$2b$12$` (bcrypt), not your password.
3. **SQL injection:** log in with the username `' OR '1'='1` and any password. It fails, because the input is treated as data, not SQL.
4. **Rate limiting:** enter the wrong password 6 times. The 6th attempt is blocked with a 429 error.
5. **Session and logout:** log in, click **Log out**, then press the browser Back button or open `/dashboard`. You are redirected to the login page.
6. **2FA:** on the dashboard click **Enable 2FA**, scan the QR code, enter the code, then log out and log in again. You are asked for a 6-digit code.

## Limitations (and what to do in production)

- Sessions use the default in-memory store. Use a persistent store such as Redis or `connect-sqlite3` in production.
- The TOTP secret is stored unencrypted in the database. Encrypt it at rest in production.
- Run behind HTTPS and set `NODE_ENV=production` so cookies are marked `Secure`.
- There is no email verification or password reset flow.
