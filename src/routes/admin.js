const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { pool } = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/role');
const { recordAudit } = require('../services/audit');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

/* ---------------------------------------------------------------------- */
/* Existing routes (unchanged behavior)                                    */
/* ---------------------------------------------------------------------- */

// GET /api/admin/users -> every user, so admin can see roles + who has
// sensitive access, and move "pending" signups into a real role.
router.get('/users', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, role, sensitive_access, disabled, created_at FROM users ORDER BY created_at DESC`
  );
  res.json(rows);
});

const roleSchema = z.object({
  role: z.enum(['pending', 'viewer', 'analyst', 'admin']),
});

// POST /api/admin/users/:id/role  { role } -> updates a user's role.
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

// POST /api/admin/users/:id/revoke-sensitive
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

// POST /api/admin/secondary-password  { newPassword }
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

// GET /api/admin/audit -> recent important actions
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

/* ---------------------------------------------------------------------- */
/* NEW: User Management extras (disable / enable / delete)                 */
/* ---------------------------------------------------------------------- */

// POST /api/admin/users/:id/disable -> blocks that user from logging in
router.post('/users/:id/disable', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET disabled = TRUE WHERE id = $1 RETURNING id, email, disabled`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });
  await recordAudit(req.user.id, 'user_disabled', { targetUser: req.params.id });
  res.json(rows[0]);
});

// POST /api/admin/users/:id/enable -> re-allows that user to log in
router.post('/users/:id/enable', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET disabled = FALSE WHERE id = $1 RETURNING id, email, disabled`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });
  await recordAudit(req.user.id, 'user_enabled', { targetUser: req.params.id });
  res.json(rows[0]);
});

// DELETE /api/admin/users/:id -> removes the account entirely
router.delete('/users/:id', async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  const { rows } = await pool.query(
    `DELETE FROM users WHERE id = $1 RETURNING id, email`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });
  await recordAudit(req.user.id, 'user_deleted', { targetUser: req.params.id, email: rows[0].email });
  res.json({ status: 'deleted' });
});

/* ---------------------------------------------------------------------- */
/* NEW: Overview stats                                                     */
/* ---------------------------------------------------------------------- */

// GET /api/admin/overview -> the numbers behind the Overview stat cards
router.get('/overview', async (req, res) => {
  const [users, pending, logs, sources, openAlerts] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS count FROM users`),
    pool.query(`SELECT COUNT(*)::int AS count FROM access_requests WHERE status = 'pending'`),
    pool.query(`SELECT COUNT(*)::int AS count FROM logs`),
    pool.query(`SELECT COUNT(*)::int AS count FROM log_sources WHERE enabled = TRUE`),
    pool.query(`SELECT COUNT(*)::int AS count FROM alerts WHERE status != 'resolved'`),
  ]);

  res.json({
    totalUsers: users.rows[0].count,
    pendingAccessRequests: pending.rows[0].count,
    logsProcessed: logs.rows[0].count,
    activeSources: sources.rows[0].count,
    openSecurityAlerts: openAlerts.rows[0].count,
  });
});

/* ---------------------------------------------------------------------- */
/* NEW: Log Sources                                                        */
/* ---------------------------------------------------------------------- */

// GET /api/admin/sources -> every ingestion source, enabled or not
router.get('/sources', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM log_sources ORDER BY name ASC`);
  res.json(rows);
});

const sourceSchema = z.object({
  name: z.string().min(1),
  vendor: z.string().optional(),
});

// POST /api/admin/sources  { name, vendor } -> adds a new ingestion source
router.post('/sources', async (req, res) => {
  const parsed = sourceSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO log_sources (name, vendor) VALUES ($1, $2) RETURNING *`,
      [parsed.data.name, parsed.data.vendor || null]
    );
    await recordAudit(req.user.id, 'log_source_added', { name: parsed.data.name });
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A source with that name already exists.' });
    }
    throw err;
  }
});

const sourceUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  vendor: z.string().optional(),
  enabled: z.boolean().optional(),
});

// PATCH /api/admin/sources/:id  { name?, vendor?, enabled? } -> edit or disable a source
router.patch('/sources/:id', async (req, res) => {
  const parsed = sourceUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { rows: existingRows } = await pool.query(`SELECT * FROM log_sources WHERE id = $1`, [req.params.id]);
  if (!existingRows[0]) return res.status(404).json({ error: 'Source not found.' });
  const current = existingRows[0];
  const next = { ...current, ...parsed.data };

  const { rows } = await pool.query(
    `UPDATE log_sources SET name = $1, vendor = $2, enabled = $3 WHERE id = $4 RETURNING *`,
    [next.name, next.vendor, next.enabled, req.params.id]
  );

  await recordAudit(req.user.id, 'log_source_updated', { id: req.params.id, changes: parsed.data });
  res.json(rows[0]);
});

/* ---------------------------------------------------------------------- */
/* NEW: Log Access (which users can see which log categories)              */
/* ---------------------------------------------------------------------- */

// GET /api/admin/log-access -> every user with the list of categories they can see
router.get('/log-access', async (req, res) => {
  const { rows: users } = await pool.query(
    `SELECT id, email FROM users ORDER BY email ASC`
  );
  const { rows: access } = await pool.query(`SELECT user_id, category FROM user_log_access`);

  const byUser = {};
  for (const row of access) {
    if (!byUser[row.user_id]) byUser[row.user_id] = [];
    byUser[row.user_id].push(row.category);
  }

  res.json(
    users.map((u) => ({ userId: u.id, email: u.email, categories: byUser[u.id] || [] }))
  );
});

const logAccessSchema = z.object({
  categories: z.array(z.string()),
});

// POST /api/admin/log-access/:userId  { categories: [...] } -> replaces the
// full set of categories that user can see.
router.post('/log-access/:userId', async (req, res) => {
  const parsed = logAccessSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM user_log_access WHERE user_id = $1`, [req.params.userId]);
    for (const category of parsed.data.categories) {
      await client.query(
        `INSERT INTO user_log_access (user_id, category) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [req.params.userId, category]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  await recordAudit(req.user.id, 'log_access_updated', {
    targetUser: req.params.userId,
    categories: parsed.data.categories,
  });
  res.json({ status: 'updated', categories: parsed.data.categories });
});

/* ---------------------------------------------------------------------- */
/* NEW: Security Alerts status updates                                     */
/* ---------------------------------------------------------------------- */

const alertStatusSchema = z.object({
  status: z.enum(['open', 'investigating', 'resolved']),
});

// POST /api/admin/alerts/:id/status  { status } -> moves an alert through
// open -> investigating -> resolved
router.post('/alerts/:id/status', async (req, res) => {
  const parsed = alertStatusSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { rows } = await pool.query(
    `UPDATE alerts SET status = $1 WHERE id = $2 RETURNING id, status`,
    [parsed.data.status, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Alert not found.' });

  await recordAudit(req.user.id, 'alert_status_changed', {
    alertId: req.params.id,
    newStatus: parsed.data.status,
  });
  res.json(rows[0]);
});

/* ---------------------------------------------------------------------- */
/* NEW: Security Control (read-only status indicators)                     */
/* ---------------------------------------------------------------------- */

// GET /api/admin/security-status -> real, current flags only. Never
// returns the AES master key itself, only whether encryption is active.
router.get('/security-status', async (req, res) => {
  res.json({
    aesEncryption: Boolean(process.env.AES_MASTER_KEY_HEX),
    masking: true, // ULPF always runs masking rules on non-sensitive views
    https: req.secure || req.headers['x-forwarded-proto'] === 'https',
    rateLimiting: true, // express-rate-limit is always mounted in server.js
    loginProtection: true, // argon2 hashing + failed-login lockout alerting is always on
  });
});

/* ---------------------------------------------------------------------- */
/* NEW: Masking Rules                                                       */
/* ---------------------------------------------------------------------- */

const DEFAULT_MASKING_FIELDS = { email: true, password: true, apiKey: true, phone: true, ip: true };

// GET /api/admin/masking-config
router.get('/masking-config', async (req, res) => {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'masking_fields'`);
  if (!rows[0]) return res.json(DEFAULT_MASKING_FIELDS);
  try {
    res.json({ ...DEFAULT_MASKING_FIELDS, ...JSON.parse(rows[0].value) });
  } catch {
    res.json(DEFAULT_MASKING_FIELDS);
  }
});

const maskingConfigSchema = z.object({
  email: z.boolean(),
  password: z.boolean(),
  apiKey: z.boolean(),
  phone: z.boolean(),
  ip: z.boolean(),
});

// POST /api/admin/masking-config  { email, password, apiKey, phone, ip }
// Applies to logs uploaded AFTER this is saved (existing logs already have
// their masked view baked in from upload time).
router.post('/masking-config', async (req, res) => {
  const parsed = maskingConfigSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('masking_fields', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [JSON.stringify(parsed.data)]
  );
  await recordAudit(req.user.id, 'masking_config_changed', parsed.data);
  res.json({ status: 'updated', config: parsed.data });
});

/* ---------------------------------------------------------------------- */
/* NEW: AI / Detection Settings                                            */
/* ---------------------------------------------------------------------- */

const DEFAULT_AI_SETTINGS = {
  anomalyDetection: true,
  threatCorrelation: true,
  aiMasking: false,
  automaticAlerts: true,
  sensitivity: 'medium',
};

// GET /api/admin/ai-settings
router.get('/ai-settings', async (req, res) => {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'ai_settings'`);
  if (!rows[0]) return res.json(DEFAULT_AI_SETTINGS);
  try {
    res.json({ ...DEFAULT_AI_SETTINGS, ...JSON.parse(rows[0].value) });
  } catch {
    res.json(DEFAULT_AI_SETTINGS);
  }
});

const aiSettingsSchema = z.object({
  anomalyDetection: z.boolean(),
  threatCorrelation: z.boolean(),
  // NOTE: ULPF's masking (utils/masking.js) is deterministic regex, not AI.
  // This toggle is stored so the screen works, but it does not currently
  // switch on any actual AI-based masking model - there isn't one yet.
  aiMasking: z.boolean(),
  automaticAlerts: z.boolean(),
  sensitivity: z.enum(['low', 'medium', 'high']),
});

// POST /api/admin/ai-settings
router.post('/ai-settings', async (req, res) => {
  const parsed = aiSettingsSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('ai_settings', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [JSON.stringify(parsed.data)]
  );
  await recordAudit(req.user.id, 'ai_settings_changed', parsed.data);
  res.json({ status: 'updated', config: parsed.data });
});

/* ---------------------------------------------------------------------- */
/* NEW: System Settings                                                    */
/* ---------------------------------------------------------------------- */

const DEFAULT_SYSTEM_SETTINGS = {
  logRetentionDays: 90,
  maxUploadSizeMb: 2,
  sessionTimeoutMinutes: 480,
  notifyOnCriticalAlerts: true,
};

// GET /api/admin/system-settings
router.get('/system-settings', async (req, res) => {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'system_settings'`);
  if (!rows[0]) return res.json(DEFAULT_SYSTEM_SETTINGS);
  try {
    res.json({ ...DEFAULT_SYSTEM_SETTINGS, ...JSON.parse(rows[0].value) });
  } catch {
    res.json(DEFAULT_SYSTEM_SETTINGS);
  }
});

const systemSettingsSchema = z.object({
  logRetentionDays: z.number().int().positive(),
  // NOTE: stored for reference; Express's actual body-size limit is set once
  // at startup in server.js (express.json({ limit: '2mb' })) and does not
  // change at runtime just because this number is saved. Changing the real
  // limit means editing that line and restarting the server.
  maxUploadSizeMb: z.number().int().positive(),
  sessionTimeoutMinutes: z.number().int().positive(),
  // NOTE: there is no email/notification system in ULPF yet. This flag is
  // stored so the screen works, but nothing currently sends a notification
  // when it's on.
  notifyOnCriticalAlerts: z.boolean(),
});

// POST /api/admin/system-settings
router.post('/system-settings', async (req, res) => {
  const parsed = systemSettingsSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('system_settings', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [JSON.stringify(parsed.data)]
  );
  await recordAudit(req.user.id, 'system_settings_changed', parsed.data);
  res.json({ status: 'updated', config: parsed.data });
});

/* ---------------------------------------------------------------------- */
/* NEW: Reports (computed on demand from real data, no fake numbers)       */
/* ---------------------------------------------------------------------- */

// GET /api/admin/reports/:type  where type is daily | weekly | security | user-activity
router.get('/reports/:type', async (req, res) => {
  const { type } = req.params;

  if (type === 'daily' || type === 'weekly') {
    const interval = type === 'daily' ? '1 day' : '7 days';
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS logs_processed,
              COUNT(*) FILTER (WHERE created_at > now() - interval '${interval}')::int AS logs_in_period
       FROM logs`
    );
    const { rows: alertRows } = await pool.query(
      `SELECT severity, COUNT(*)::int AS count FROM alerts
       WHERE created_at > now() - interval '${interval}' GROUP BY severity`
    );
    return res.json({ type, generatedAt: new Date().toISOString(), ...rows[0], alertsBySeverity: alertRows });
  }

  if (type === 'security') {
    const { rows: bySeverity } = await pool.query(
      `SELECT severity, status, COUNT(*)::int AS count FROM alerts GROUP BY severity, status`
    );
    return res.json({ type, generatedAt: new Date().toISOString(), alerts: bySeverity });
  }

  if (type === 'user-activity') {
    const { rows } = await pool.query(
      `SELECT u.email, COUNT(al.id)::int AS actions
       FROM users u LEFT JOIN audit_log al ON al.user_id = u.id
       GROUP BY u.email ORDER BY actions DESC LIMIT 50`
    );
    return res.json({ type, generatedAt: new Date().toISOString(), users: rows });
  }

  res.status(400).json({ error: 'Unknown report type. Use daily, weekly, security, or user-activity.' });
});

module.exports = router;
