const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { pool } = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/role');
const { recordAudit } = require('../services/audit');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

// GET /api/admin/users -> every user, so admin can see roles + who has
// sensitive access, and move "pending" signups into a real role.
router.get('/users', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, role, sensitive_access, created_at FROM users ORDER BY created_at DESC`
  );
  res.json(rows);
});

const roleSchema = z.object({
  role: z.enum(['pending', 'viewer', 'analyst', 'admin']),
});

// POST /api/admin/users/:id/role  { role } -> updates a user's role.
// This is how a brand-new "pending" signup becomes a real viewer/analyst,
// and how an admin can promote or demote anyone else.
router.post('/users/:id/role', async (req, res) => {
  const parsed = roleSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const { rows } = await pool.query(
    `UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, role`,
    [parsed.data.role, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });

  await recordAudit(req.user.id, 'user_role_changed', {
    targetUser: req.params.id,
    newRole: parsed.data.role,
  });

  res.json(rows[0]);
});

// POST /api/admin/users/:id/revoke-sensitive -> takes away sensitive access
// at any time, independent of role, per the "access should be revocable"
// requirement.
router.post('/users/:id/revoke-sensitive', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET sensitive_access = FALSE WHERE id = $1 RETURNING id, email`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });

  await recordAudit(req.user.id, 'sensitive_access_revoked', { targetUser: req.params.id });
  res.json({ status: 'revoked' });
});

const passwordSchema = z.object({
  newPassword: z.string().min(8, 'Password must be at least 8 characters.'),
});

// POST /api/admin/secondary-password  { newPassword } -> sets/updates the
// one shared unlock code required to view sensitive logs.
router.post('/secondary-password', async (req, res) => {
  const parsed = passwordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const hash = await argon2.hash(parsed.data.newPassword, { type: argon2.argon2id });
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('secondary_password_hash', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [hash]
  );

  await recordAudit(req.user.id, 'secondary_password_changed', {});
  res.json({ status: 'updated' });
});

// GET /api/admin/audit -> recent important actions, for the Security
// Status / Settings page.
router.get('/audit', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT al.id, al.action, al.details, al.created_at, u.email AS user_email
     FROM audit_log al
     LEFT JOIN users u ON u.id = al.user_id
     ORDER BY al.created_at DESC
     LIMIT 200`
  );
  res.json(rows);
});

module.exports = router;
