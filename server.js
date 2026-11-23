/**
 * Secure Login System
 * - Registration + login with bcrypt-hashed passwords
 * - Input validation (Joi) and SQL injection protection (parameterized queries)
 * - Session management with logout (session regenerated on login)
 * - Optional Two-Factor Authentication (TOTP, e.g. Google Authenticator)
 * - Extras: helmet security headers, rate limiting, CSRF tokens, secure logging
 */
require('dotenv').config();

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const Database = require('better-sqlite3');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const winston = require('winston');

// ---------- Config (secrets come from environment variables) ----------
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET is missing or too short. Copy .env.example to .env and set it.');
  process.exit(1);
}
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';
const SALT_ROUNDS = 12;
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', SALT_ROUNDS); // equalises timing for unknown users

// ---------- Logging ----------
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'security.log') }),
  ],
});

// ---------- Database (every query is parameterized) ----------
const db = new Database(path.join(__dirname, 'users.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);
const sql = {
  byId: db.prepare('SELECT * FROM users WHERE id = ?'),
  byLogin: db.prepare('SELECT * FROM users WHERE username = ? OR email = ?'),
  insert: db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'),
  enable2fa: db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?'),
  disable2fa: db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?'),
};

// ---------- Input validation ----------
const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().max(100).required(),
  password: Joi.string()
    .min(8).max(72) // bcrypt only uses the first 72 bytes
    .pattern(/[a-z]/, 'lowercase').pattern(/[A-Z]/, 'uppercase')
    .pattern(/[0-9]/, 'number').pattern(/[^A-Za-z0-9]/, 'symbol')
    .required()
    .messages({ 'string.pattern.name': 'Password must include a lowercase letter, an uppercase letter, a number and a symbol.' }),
  confirm: Joi.any().valid(Joi.ref('password')).required().messages({ 'any.only': 'Passwords do not match.' }),
  _csrf: Joi.any(),
});
const loginSchema = Joi.object({
  identifier: Joi.string().max(100).required(),
  password: Joi.string().max(128).required(),
  _csrf: Joi.any(),
});
const codeSchema = Joi.object({ code: Joi.string().pattern(/^\d{6}$/).required(), _csrf: Joi.any() });

// ---------- HTML helpers (all output is escaped to prevent XSS) ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const page = (title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
 body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;padding:40px 16px}
 .card{background:#1e293b;border-radius:12px;padding:28px;width:100%;max-width:400px;box-shadow:0 8px 30px #0006}
 h1{margin-top:0;font-size:1.4rem} label{display:block;margin:14px 0 4px;font-size:.9rem}
 input{width:100%;padding:10px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;box-sizing:border-box}
 button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
 button.danger{background:#dc2626} a{color:#60a5fa}
 .err{background:#7f1d1d;padding:10px;border-radius:8px;margin-bottom:10px}
 .ok{background:#14532d;padding:10px;border-radius:8px;margin-bottom:10px}
 code{word-break:break-all} img{background:#fff;border-radius:8px;display:block;margin:10px auto}
</style></head><body><div class="card">${body}</div></body></html>`;
const csrfField = (req) => `<input type="hidden" name="_csrf" value="${esc(req.session.csrf)}">`;
const msg = (text, cls = 'err') => (text ? `<div class="${cls}">${esc(text)}</div>` : '');

const registerPage = (req, error) => page('Register', `
  <h1>Create account</h1>${msg(error)}
  <form method="POST" action="/register" autocomplete="off">${csrfField(req)}
    <label>Username</label><input name="username" required minlength="3" maxlength="30">
    <label>Email</label><input name="email" type="email" required maxlength="100">
    <label>Password</label><input name="password" type="password" required minlength="8" maxlength="72">
    <label>Confirm password</label><input name="confirm" type="password" required>
    <button>Register</button>
  </form><p>Already registered? <a href="/login">Log in</a></p>`);

const loginPage = (req, error, ok) => page('Login', `
  <h1>Log in</h1>${msg(ok, 'ok')}${msg(error)}
  <form method="POST" action="/login">${csrfField(req)}
    <label>Username or email</label><input name="identifier" required maxlength="100">
    <label>Password</label><input name="password" type="password" required maxlength="128">
    <button>Log in</button>
  </form><p>No account? <a href="/register">Register</a></p>`);

const verifyPage = (req, error) => page('Two-factor authentication', `
  <h1>Two-factor authentication</h1>${msg(error)}
  <p>Enter the 6-digit code from your authenticator app.</p>
  <form method="POST" action="/2fa/verify">${csrfField(req)}
    <input name="code" inputmode="numeric" pattern="\\d{6}" maxlength="6" required autofocus>
    <button>Verify</button>
  </form>`);

// ---------- App + security middleware ----------
const app = express();
if (isProd) app.set('trust proxy', 1); // needed behind a reverse proxy so secure cookies/IP limits work
app.use(helmet()); // CSP, HSTS, noSniff, frameguard, hides X-Powered-By, etc.
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false, message: 'Too many requests from this IP' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'strict', secure: isProd, maxAge: 30 * 60 * 1000 }, // 30 min idle timeout
}));

// CSRF token per session; every POST must send it back
app.use((req, res, next) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  next();
});
function csrfCheck(req, res, next) {
  const a = Buffer.from(String(req.body._csrf || ''));
  const b = Buffer.from(req.session.csrf);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    logger.warn('CSRF check failed', { ip: req.ip, path: req.path });
    return res.status(403).send(page('Forbidden', '<h1>Invalid request</h1><p><a href="/login">Back</a></p>'));
  }
  next();
}
const requireAuth = (req, res, next) => (req.session.userId ? next() : res.redirect('/login'));

// New session id on every login step (prevents session fixation)
function startSession(req, data, cb) {
  req.session.regenerate((err) => {
    if (err) return cb(err);
    Object.assign(req.session, data, { csrf: crypto.randomBytes(32).toString('hex') });
    cb(null);
  });
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => { logger.warn('Login rate limit hit', { ip: req.ip }); res.status(429).send(loginPage(req, 'Too many failed attempts. Try again in 15 minutes.')); } });
const codeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

const verifyTotp = (secret, token) => speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });

// ---------- Routes ----------
app.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login'));

app.get('/register', (req, res) => res.send(registerPage(req)));
app.post('/register', csrfCheck, async (req, res, next) => {
  try {
    const { error, value } = registerSchema.validate(req.body, { abortEarly: true, stripUnknown: true });
    if (error) return res.status(400).send(registerPage(req, error.details[0].message.replace(/"/g, '')));
    const hash = await bcrypt.hash(value.password, SALT_ROUNDS);
    try {
      sql.insert.run(value.username, value.email.toLowerCase(), hash);
    } catch (e) {
      if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).send(registerPage(req, 'Username or email is already in use.'));
      throw e;
    }
    logger.info('User registered', { username: value.username });
    res.send(loginPage(req, null, 'Account created. Please log in.'));
  } catch (err) { next(err); }
});

app.get('/login', (req, res) => (req.session.userId ? res.redirect('/dashboard') : res.send(loginPage(req))));
app.post('/login', loginLimiter, csrfCheck, async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body, { stripUnknown: true });
    if (error) return res.status(400).send(loginPage(req, 'Invalid username or password.'));
    const id = value.identifier.trim();
    const user = sql.byLogin.get(id, id.toLowerCase());
    const ok = await bcrypt.compare(value.password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) {
      logger.warn('Failed login', { ip: req.ip, identifier: id });
      return res.status(401).send(loginPage(req, 'Invalid username or password.')); // same message either way
    }
    if (user.totp_enabled) {
      return startSession(req, { pending2fa: user.id, pendingAt: Date.now() }, (e) => (e ? next(e) : res.redirect('/2fa/verify')));
    }
    startSession(req, { userId: user.id }, (e) => {
      if (e) return next(e);
      logger.info('Login success', { userId: user.id, ip: req.ip });
      res.redirect('/dashboard');
    });
  } catch (err) { next(err); }
});

app.get('/2fa/verify', (req, res) => (req.session.pending2fa ? res.send(verifyPage(req)) : res.redirect('/login')));
app.post('/2fa/verify', codeLimiter, csrfCheck, (req, res, next) => {
  const pending = req.session.pending2fa;
  if (!pending || Date.now() - req.session.pendingAt > 5 * 60 * 1000) return res.redirect('/login');
  const { error, value } = codeSchema.validate(req.body, { stripUnknown: true });
  const user = sql.byId.get(pending);
  if (error || !user || !verifyTotp(user.totp_secret, value.code)) {
    logger.warn('Failed 2FA code', { userId: pending, ip: req.ip });
    return res.status(401).send(verifyPage(req, 'Invalid code.'));
  }
  startSession(req, { userId: user.id }, (e) => {
    if (e) return next(e);
    logger.info('Login success (2FA)', { userId: user.id, ip: req.ip });
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  const user = sql.byId.get(req.session.userId);
  if (!user) return res.redirect('/login');
  const twofa = user.totp_enabled
    ? `<p>Two-factor authentication: <b>ON</b></p>
       <form method="POST" action="/2fa/disable">${csrfField(req)}<button class="danger">Disable 2FA</button></form>`
    : `<p>Two-factor authentication: <b>OFF</b></p><a href="/2fa/setup">Enable 2FA</a>`;
  res.send(page('Dashboard', `
    <h1>Welcome, ${esc(user.username)}</h1>${msg(req.query.ok ? '2FA updated.' : '', 'ok')}
    <p>You are logged in securely.</p>${twofa}
    <form method="POST" action="/logout">${csrfField(req)}<button>Log out</button></form>`));
});

app.get('/2fa/setup', requireAuth, async (req, res, next) => {
  try {
    const user = sql.byId.get(req.session.userId);
    if (user.totp_enabled) return res.redirect('/dashboard');
    const secret = speakeasy.generateSecret({ length: 20, name: `SecureLogin (${user.username})` });
    req.session.pendingSecret = secret.base32;
    const qr = await QRCode.toDataURL(secret.otpauth_url);
    res.send(page('Enable 2FA', `
      <h1>Enable 2FA</h1>
      <p>Scan this QR code with Google Authenticator or Authy, then enter the 6-digit code.</p>
      <img src="${qr}" alt="2FA QR code" width="200" height="200">
      <p>Manual key: <code>${esc(secret.base32)}</code></p>
      <form method="POST" action="/2fa/enable">${csrfField(req)}
        <input name="code" inputmode="numeric" pattern="\\d{6}" maxlength="6" required>
        <button>Confirm and enable</button></form>`));
  } catch (err) { next(err); }
});
app.post('/2fa/enable', requireAuth, codeLimiter, csrfCheck, (req, res) => {
  const { error, value } = codeSchema.validate(req.body, { stripUnknown: true });
  const secret = req.session.pendingSecret;
  if (error || !secret || !verifyTotp(secret, value.code)) return res.status(400).send(page('Enable 2FA', '<h1>Invalid code</h1><p><a href="/2fa/setup">Try again</a></p>'));
  sql.enable2fa.run(secret, req.session.userId);
  delete req.session.pendingSecret;
  logger.info('2FA enabled', { userId: req.session.userId });
  res.redirect('/dashboard?ok=1');
});
app.post('/2fa/disable', requireAuth, csrfCheck, (req, res) => {
  sql.disable2fa.run(req.session.userId);
  logger.info('2FA disabled', { userId: req.session.userId });
  res.redirect('/dashboard?ok=1');
});

// Logout: destroy the server-side session and clear the cookie
app.post('/logout', csrfCheck, (req, res, next) => {
  const userId = req.session.userId;
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid');
    logger.info('Logout', { userId });
    res.redirect('/login');
  });
});

// ---------- Error handling (never leak stack traces in production) ----------
app.use((req, res) => res.status(404).send(page('Not found', '<h1>404</h1><p><a href="/">Home</a></p>')));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  logger.error(err.stack);
  const message = isProd ? 'Internal Server Error' : err.message;
  res.status(500).send(page('Error', `<h1>Something went wrong</h1><p>${esc(message)}</p>`));
});

app.listen(PORT, () => logger.info(`Secure login system running on http://localhost:${PORT}`));
