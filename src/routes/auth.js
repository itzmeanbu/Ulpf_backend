const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { pool } = require('../db');
const { checkFailedLogins } = require('../services/alerts');
const { recordAudit } = require('../services/audit');

const router = express.Router();

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters.'),
});

// POST /api/auth/register  { email, password } -> { status: "pending" }
// New accounts start with role "pending" - an admin has to move them to
// viewer/analyst before they can actually log in and see anything.
router.post('/register', async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { email, password } = parsed.data;

  try {
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    await pool.query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'pending')`,
      [email, hash]
    );
    res.status(201).json({ status: 'pending' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// NEW: reads the admin-configured session timeout (minutes) from the
// System Settings screen. Falls back to the old JWT_EXPIRES_IN env var
// (or 8h) if nothing has been saved yet.
async function getSessionTimeoutMinutes() {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'system_settings'`);
  if (!rows[0]) return null;
  try {
    const parsed = JSON.parse(rows[0].value);
    return parsed.sessionTimeoutMinutes || null;
  } catch {
    return null;
  }
}

// POST /api/auth/login  { email, password } -> { token, role }
router.post('/login', async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { email, password } = parsed.data;

  const { rows } = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
  const user = rows[0];

  const valid = user ? await argon2.verify(user.password_hash, password) : false;

  await pool.query(
    `INSERT INTO login_attempts (email, success) VALUES ($1, $2)`,
    [email, valid]
  );

  if (!valid) {
    await checkFailedLogins(email);
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  if (user.role === 'pending') {
    return res.status(403).json({ error: 'Your account is awaiting admin approval.' });
  }

  // NEW: a disabled user (see admin User Management) can never get a token,
  // even if their email/password are correct and their role is fine.
  if (user.disabled) {
    return res.status(403).json({ error: 'This account has been disabled.' });
  }

  const timeoutMinutes = await getSessionTimeoutMinutes();
  const expiresIn = timeoutMinutes ? `${timeoutMinutes}m` : (process.env.JWT_EXPIRES_IN || '8h');

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      sensitiveAccess: user.sensitive_access,
    },
    process.env.JWT_SECRET,
    { expiresIn }
  );

  await recordAudit(user.id, 'login', {});
  res.json({ token, role: user.role });
});

module.exports = router;
