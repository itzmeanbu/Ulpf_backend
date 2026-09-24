import express from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { pool } from '../db';
import { checkFailedLogins } from '../services/alerts';
import { recordAudit } from '../services/audit';
import { requireAuth } from '../middleware/auth';

const router = express.Router();

const credentialsSchema = z.object({
  email: z.string().email().trim().toLowerCase(),
  password: z.string().min(8, 'Password must be at least 8 characters.').trim(),
});

// POST /api/auth/register  { email, password } -> { status: "pending" }
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
  } catch (err: any) {
    if (err.code === '23505') {
      return res.status(201).json({ status: 'pending' });
    }
    res.status(500).json({ error: 'Registration failed.' });
  }
});

async function getSessionTimeoutMinutes(): Promise<number | null> {
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

  // A soft-deleted account (in the Recycle Bin) behaves as if it doesn't exist.
  if (user.deleted_at) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  if (user.role === 'pending') {
    return res.status(403).json({ error: 'Your account is awaiting admin approval.' });
  }

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
    process.env.JWT_SECRET as string,
    { expiresIn } as jwt.SignOptions
  );

  await recordAudit(user.id, 'login', {});
  res.json({ token, role: user.role });
});

// GET /api/auth/me  -> { id, email, role, sensitive_access }
router.get('/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, role, sensitive_access FROM users WHERE id = $1`,
    [req.user!.id]
  );
  if (!rows[0]) {
    return res.status(404).json({ error: 'User not found.' });
  }
  res.json(rows[0]);
});

export default router;
