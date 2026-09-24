import express from 'express';
import argon2 from 'argon2';
import { z } from 'zod';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/role';
import { recordAudit } from '../services/audit';

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

// There is exactly ONE admin. It is created from the server environment
// variables (BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD) and can only be
// changed there. Nothing in this panel may touch that account - including
// the Recycle Bin, which can never hold the admin account.
router.use('/users/:id', async (req, res, next) => {
  try {
    const { rows } = await pool.query(`SELECT role FROM users WHERE id = $1`, [req.params.id]);
    if (rows[0] && rows[0].role === 'admin') {
      return res.status(403).json({
        error: 'The admin account is permanent. It can only be changed in the server environment variables.',
      });
    }
    next();
  } catch (err) {
    next(err);
  }
});

/* ---------------------------------------------------------------------- */
/* Users                                                                    */
/* ---------------------------------------------------------------------- */

// GET /api/admin/users -> every ACTIVE (non-deleted) user
router.get('/users', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, role, sensitive_access, disabled, created_at
     FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC`
  );
  res.json(rows);
});

const roleSchema = z.object({
  role: z.enum(['pending', 'viewer', 'analyst']),
});

// POST /api/admin/users/:id/role  { role } -> updates a user's role.
router.post('/users/:id/role', async (req, res) => {
  const parsed = roleSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const { rows } = await pool.query(
    `UPDATE users SET role = $1 WHERE id = $2 AND deleted_at IS NULL RETURNING id, email, role`,
    [parsed.data.role, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });

  await recordAudit(req.user!.id, 'user_role_changed', {
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

  await recordAudit(req.user!.id, 'sensitive_access_revoked', { targetUser: req.params.id });
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

  await recordAudit(req.user!.id, 'secondary_password_changed', {});
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
/* User Management extras (disable / enable / delete-to-recycle-bin)       */
/* ---------------------------------------------------------------------- */

// POST /api/admin/users/:id/disable -> blocks that user from logging in
router.post('/users/:id/disable', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET disabled = TRUE WHERE id = $1 AND deleted_at IS NULL RETURNING id, email, disabled`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });
  await recordAudit(req.user!.id, 'user_disabled', { targetUser: req.params.id });
  res.json(rows[0]);
});

// POST /api/admin/users/:id/enable -> re-allows that user to log in
router.post('/users/:id/enable', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET disabled = FALSE WHERE id = $1 AND deleted_at IS NULL RETURNING id, email, disabled`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });
  await recordAudit(req.user!.id, 'user_enabled', { targetUser: req.params.id });
  res.json(rows[0]);
});

// DELETE /api/admin/users/:id -> moves the account to the Recycle Bin
// (soft delete). The account can no longer log in, but nothing about it is
// destroyed until it is permanently deleted from Admin > Recycle Bin.
router.delete('/users/:id', async (req, res) => {
  if (req.params.id === req.user!.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  const { rows } = await pool.query(
    `UPDATE users SET deleted_at = now(), deleted_by = $1
     WHERE id = $2 AND deleted_at IS NULL RETURNING id, email`,
    [req.user!.id, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });

  await recordAudit(req.user!.id, 'user_deleted', { targetUser: req.params.id, email: rows[0].email });
  res.json({ status: 'deleted' });
});

/* ---------------------------------------------------------------------- */
/* Overview stats                                                          */
/* ---------------------------------------------------------------------- */

// GET /api/admin/overview -> the numbers behind the Overview stat cards
router.get('/overview', async (req, res) => {
  const [users, pending, logs, sources, openAlerts] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS count FROM users WHERE deleted_at IS NULL`),
    pool.query(`SELECT COUNT(*)::int AS count FROM access_requests WHERE status = 'pending'`),
    pool.query(`SELECT COUNT(*)::int AS count FROM logs WHERE deleted_at IS NULL`),
    pool.query(`SELECT COUNT(*)::int AS count FROM log_sources WHERE enabled = TRUE AND deleted_at IS NULL`),
    pool.query(`SELECT COUNT(*)::int AS count FROM alerts WHERE status != 'resolved' AND deleted_at IS NULL`),
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
/* Log Sources                                                             */
/* ---------------------------------------------------------------------- */

// GET /api/admin/sources -> every active ingestion source, enabled or not
router.get('/sources', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM log_sources WHERE deleted_at IS NULL ORDER BY name ASC`);
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
    await recordAudit(req.user!.id, 'log_source_added', { name: parsed.data.name });
    res.status(201).json(rows[0]);
  } catch (err: any) {
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
  const { rows: existingRows } = await pool.query(`SELECT * FROM log_sources WHERE id = $1 AND deleted_at IS NULL`, [req.params.id]);
  if (!existingRows[0]) return res.status(404).json({ error: 'Source not found.' });
  const current = existingRows[0];
  const next = { ...current, ...parsed.data };

  const { rows } = await pool.query(
    `UPDATE log_sources SET name = $1, vendor = $2, enabled = $3 WHERE id = $4 RETURNING *`,
    [next.name, next.vendor, next.enabled, req.params.id]
  );

  await recordAudit(req.user!.id, 'log_source_updated', { id: req.params.id, changes: parsed.data });
  res.json(rows[0]);
});

// DELETE /api/admin/sources/:id -> moves the source to the Recycle Bin
router.delete('/sources/:id', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE log_sources SET deleted_at = now(), deleted_by = $1
     WHERE id = $2 AND deleted_at IS NULL RETURNING id, name`,
    [req.user!.id, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Source not found.' });
  await recordAudit(req.user!.id, 'log_source_deleted', { id: req.params.id, name: rows[0].name });
  res.json({ status: 'deleted' });
});

/* ---------------------------------------------------------------------- */
/* Log Access                                                              */
/* ---------------------------------------------------------------------- */

router.get('/log-access', async (req, res) => {
  const { rows: users } = await pool.query(
    `SELECT id, email FROM users WHERE deleted_at IS NULL ORDER BY email ASC`
  );
  const { rows: access } = await pool.query(`SELECT user_id, category FROM user_log_access`);

  const byUser: Record<string, string[]> = {};
  for (const row of access) {
    if (!byUser[row.user_id]) byUser[row.user_id] = [];
    byUser[row.user_id].push(row.category);
  }

  res.json(
    users.map((u: any) => ({ userId: u.id, email: u.email, categories: byUser[u.id] || [] }))
  );
});

const logAccessSchema = z.object({
  categories: z.array(z.string()),
});

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

  await recordAudit(req.user!.id, 'log_access_updated', {
    targetUser: req.params.userId,
    categories: parsed.data.categories,
  });
  res.json({ status: 'updated', categories: parsed.data.categories });
});

/* ---------------------------------------------------------------------- */
/* Security Alerts status updates + delete                                 */
/* ---------------------------------------------------------------------- */

const alertStatusSchema = z.object({
  status: z.enum(['open', 'investigating', 'resolved']),
});

router.post('/alerts/:id/status', async (req, res) => {
  const parsed = alertStatusSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { rows } = await pool.query(
    `UPDATE alerts SET status = $1 WHERE id = $2 AND deleted_at IS NULL RETURNING id, status`,
    [parsed.data.status, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Alert not found.' });

  await recordAudit(req.user!.id, 'alert_status_changed', {
    alertId: req.params.id,
    newStatus: parsed.data.status,
  });
  res.json(rows[0]);
});

// DELETE /api/admin/alerts/:id -> moves the alert to the Recycle Bin
router.delete('/alerts/:id', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE alerts SET deleted_at = now(), deleted_by = $1
     WHERE id = $2 AND deleted_at IS NULL RETURNING id`,
    [req.user!.id, req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Alert not found.' });
  await recordAudit(req.user!.id, 'alert_deleted', { alertId: req.params.id });
  res.json({ status: 'deleted' });
});

/* ---------------------------------------------------------------------- */
/* Security Control (read-only status indicators)                          */
/* ---------------------------------------------------------------------- */

router.get('/security-status', async (req, res) => {
  res.json({
    aesEncryption: Boolean(process.env.AES_MASTER_KEY_HEX),
    masking: true,
    https: req.secure || req.headers['x-forwarded-proto'] === 'https',
    rateLimiting: true,
    loginProtection: true,
  });
});

/* ---------------------------------------------------------------------- */
/* Masking Rules                                                           */
/* ---------------------------------------------------------------------- */

const DEFAULT_MASKING_FIELDS = { email: true, password: true, apiKey: true, phone: true, ip: true };

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
  await recordAudit(req.user!.id, 'masking_config_changed', parsed.data);
  res.json({ status: 'updated', config: parsed.data });
});

/* ---------------------------------------------------------------------- */
/* AI / Detection Settings                                                 */
/* ---------------------------------------------------------------------- */

const DEFAULT_AI_SETTINGS = {
  anomalyDetection: true,
  threatCorrelation: true,
  aiMasking: false,
  automaticAlerts: true,
  sensitivity: 'medium',
};

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
  aiMasking: z.boolean(),
  automaticAlerts: z.boolean(),
  sensitivity: z.enum(['low', 'medium', 'high']),
});

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
  await recordAudit(req.user!.id, 'ai_settings_changed', parsed.data);
  res.json({ status: 'updated', config: parsed.data });
});

/* ---------------------------------------------------------------------- */
/* System Settings                                                         */
/* ---------------------------------------------------------------------- */

const DEFAULT_SYSTEM_SETTINGS = {
  logRetentionDays: 90,
  maxUploadSizeMb: 2,
  sessionTimeoutMinutes: 480,
  notifyOnCriticalAlerts: true,
};

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
  maxUploadSizeMb: z.number().int().positive(),
  sessionTimeoutMinutes: z.number().int().positive(),
  notifyOnCriticalAlerts: z.boolean(),
});

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
  await recordAudit(req.user!.id, 'system_settings_changed', parsed.data);
  res.json({ status: 'updated', config: parsed.data });
});

/* ---------------------------------------------------------------------- */
/* Reports                                                                  */
/* ---------------------------------------------------------------------- */

router.get('/reports/:type', async (req, res) => {
  const { type } = req.params;

  if (type === 'daily' || type === 'weekly') {
    const interval = type === 'daily' ? '1 day' : '7 days';
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS logs_processed,
              COUNT(*) FILTER (WHERE created_at > now() - interval '${interval}')::int AS logs_in_period
       FROM logs WHERE deleted_at IS NULL`
    );
    const { rows: alertRows } = await pool.query(
      `SELECT severity, COUNT(*)::int AS count FROM alerts
       WHERE created_at > now() - interval '${interval}' AND deleted_at IS NULL GROUP BY severity`
    );
    return res.json({ type, generatedAt: new Date().toISOString(), ...rows[0], alertsBySeverity: alertRows });
  }

  if (type === 'security') {
    const { rows: bySeverity } = await pool.query(
      `SELECT severity, status, COUNT(*)::int AS count FROM alerts WHERE deleted_at IS NULL GROUP BY severity, status`
    );
    return res.json({ type, generatedAt: new Date().toISOString(), alerts: bySeverity });
  }

  if (type === 'user-activity') {
    const { rows } = await pool.query(
      `SELECT u.email, COUNT(al.id)::int AS actions
       FROM users u LEFT JOIN audit_log al ON al.user_id = u.id
       WHERE u.deleted_at IS NULL
       GROUP BY u.email ORDER BY actions DESC LIMIT 50`
    );
    return res.json({ type, generatedAt: new Date().toISOString(), users: rows });
  }

  res.status(400).json({ error: 'Unknown report type. Use daily, weekly, security, or user-activity.' });
});

/* ---------------------------------------------------------------------- */
/* RECYCLE BIN — accounts, alerts and log sources.                         */
/* Multiple "pages" (categories), each with select-all / restore /         */
/* permanently-delete / empty, exactly like the Logs recycle bin.          */
/* ---------------------------------------------------------------------- */

// Permanently removes a user and everything that only exists to point at
// them (mirrors the app's original hard-delete behavior).
async function hardDeleteUser(id: string): Promise<{ id: string; email: string } | null> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM user_log_access WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM access_requests WHERE user_id = $1`, [id]);
    await client.query(`UPDATE logs SET uploaded_by = NULL WHERE uploaded_by = $1`, [id]);
    await client.query(`UPDATE audit_log SET user_id = NULL WHERE user_id = $1`, [id]);
    const { rows } = await client.query(
      `DELETE FROM users WHERE id = $1 RETURNING id, email`,
      [id]
    );
    await client.query('COMMIT');
    return rows[0] || null;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// GET /api/admin/recycle-bin/summary -> item counts per category, for tab badges
router.get('/recycle-bin/summary', async (req, res) => {
  const [logs, accounts, alerts, sources] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS count FROM logs WHERE deleted_at IS NOT NULL`),
    pool.query(`SELECT COUNT(*)::int AS count FROM users WHERE deleted_at IS NOT NULL`),
    pool.query(`SELECT COUNT(*)::int AS count FROM alerts WHERE deleted_at IS NOT NULL`),
    pool.query(`SELECT COUNT(*)::int AS count FROM log_sources WHERE deleted_at IS NOT NULL`),
  ]);
  res.json({
    logs: logs.rows[0].count,
    accounts: accounts.rows[0].count,
    alerts: alerts.rows[0].count,
    sources: sources.rows[0].count,
  });
});

// GET /api/admin/recycle-bin/accounts -> deleted user accounts
router.get('/recycle-bin/accounts', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.role, u.sensitive_access, u.deleted_at, d.email AS deleted_by_email
     FROM users u LEFT JOIN users d ON d.id = u.deleted_by
     WHERE u.deleted_at IS NOT NULL ORDER BY u.deleted_at DESC`
  );
  res.json(rows);
});

const idsSchema = z.object({ ids: z.array(z.string()).min(1, 'No items selected.') });

router.post('/recycle-bin/accounts/:id/restore', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE users SET deleted_at = NULL, deleted_by = NULL
     WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id, email`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Account not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'user_restored', { targetUser: req.params.id });
  res.json({ status: 'restored' });
});

router.post('/recycle-bin/accounts/restore-bulk', async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { rows } = await pool.query(
    `UPDATE users SET deleted_at = NULL, deleted_by = NULL
     WHERE id = ANY($1::uuid[]) AND deleted_at IS NOT NULL RETURNING id`,
    [parsed.data.ids]
  );
  await recordAudit(req.user!.id, 'users_bulk_restored', { count: rows.length });
  res.json({ status: 'restored', count: rows.length });
});

router.delete('/recycle-bin/accounts/:id', async (req, res) => {
  const { rows: check } = await pool.query(`SELECT id FROM users WHERE id = $1 AND deleted_at IS NOT NULL`, [req.params.id]);
  if (!check[0]) return res.status(404).json({ error: 'Account not found in the recycle bin.' });
  const deleted = await hardDeleteUser(req.params.id);
  if (!deleted) return res.status(404).json({ error: 'Account not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'user_permanently_deleted', { targetUser: req.params.id, email: deleted.email });
  res.json({ status: 'permanently_deleted' });
});

router.post('/recycle-bin/accounts/permanent-delete-bulk', async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  let count = 0;
  for (const id of parsed.data.ids) {
    const { rows: check } = await pool.query(`SELECT id FROM users WHERE id = $1 AND deleted_at IS NOT NULL`, [id]);
    if (check[0] && (await hardDeleteUser(id))) count++;
  }
  await recordAudit(req.user!.id, 'users_bulk_permanently_deleted', { count });
  res.json({ status: 'permanently_deleted', count });
});

router.post('/recycle-bin/accounts/empty', async (req, res) => {
  const { rows } = await pool.query(`SELECT id FROM users WHERE deleted_at IS NOT NULL`);
  let count = 0;
  for (const row of rows) {
    if (await hardDeleteUser(row.id)) count++;
  }
  await recordAudit(req.user!.id, 'accounts_recycle_bin_emptied', { count });
  res.json({ status: 'emptied', count });
});

// --- Alerts recycle bin ---

router.get('/recycle-bin/alerts', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT a.*, u.email AS deleted_by_email
     FROM alerts a LEFT JOIN users u ON u.id = a.deleted_by
     WHERE a.deleted_at IS NOT NULL ORDER BY a.deleted_at DESC`
  );
  res.json(rows);
});

router.post('/recycle-bin/alerts/:id/restore', async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE alerts SET deleted_at = NULL, deleted_by = NULL
     WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Alert not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'alert_restored', { alertId: req.params.id });
  res.json({ status: 'restored' });
});

router.post('/recycle-bin/alerts/restore-bulk', async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { rows } = await pool.query(
    `UPDATE alerts SET deleted_at = NULL, deleted_by = NULL
     WHERE id = ANY($1::uuid[]) AND deleted_at IS NOT NULL RETURNING id`,
    [parsed.data.ids]
  );
  await recordAudit(req.user!.id, 'alerts_bulk_restored', { count: rows.length });
  res.json({ status: 'restored', count: rows.length });
});

router.delete('/recycle-bin/alerts/:id', async (req, res) => {
  const { rows } = await pool.query(
    `DELETE FROM alerts WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Alert not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'alert_permanently_deleted', { alertId: req.params.id });
  res.json({ status: 'permanently_deleted' });
});

router.post('/recycle-bin/alerts/permanent-delete-bulk', async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { rows } = await pool.query(
    `DELETE FROM alerts WHERE id = ANY($1::uuid[]) AND deleted_at IS NOT NULL RETURNING id`,
    [parsed.data.ids]
  );
  await recordAudit(req.user!.id, 'alerts_bulk_permanently_deleted', { count: rows.length });
  res.json({ status: 'permanently_deleted', count: rows.length });
});

router.post('/recycle-bin/alerts/empty', async (req, res) => {
  const { rows } = await pool.query(`DELETE FROM alerts WHERE deleted_at IS NOT NULL RETURNING id`);
  await recordAudit(req.user!.id, 'alerts_recycle_bin_emptied', { count: rows.length });
  res.json({ status: 'emptied', count: rows.length });
});

// --- Log sources recycle bin ---

router.get('/recycle-bin/sources', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT s.*, u.email AS deleted_by_email
     FROM log_sources s LEFT JOIN users u ON u.id = s.deleted_by
     WHERE s.deleted_at IS NOT NULL ORDER BY s.deleted_at DESC`
  );
  res.json(rows);
});

router.post('/recycle-bin/sources/:id/restore', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE log_sources SET deleted_at = NULL, deleted_by = NULL
       WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id`,
      [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Source not found in the recycle bin.' });
    await recordAudit(req.user!.id, 'log_source_restored', { id: req.params.id });
    res.json({ status: 'restored' });
  } catch (err: any) {
    if (err.code === '23505') return res.status(409).json({ error: 'A source with that name already exists.' });
    throw err;
  }
});

router.post('/recycle-bin/sources/restore-bulk', async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  let count = 0;
  for (const id of parsed.data.ids) {
    try {
      const { rows } = await pool.query(
        `UPDATE log_sources SET deleted_at = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id`,
        [id]
      );
      if (rows[0]) count++;
    } catch {
      // name collision with an active source - skip it, the rest still restore
    }
  }
  await recordAudit(req.user!.id, 'sources_bulk_restored', { count });
  res.json({ status: 'restored', count });
});

router.delete('/recycle-bin/sources/:id', async (req, res) => {
  const { rows } = await pool.query(
    `DELETE FROM log_sources WHERE id = $1 AND deleted_at IS NOT NULL RETURNING id`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Source not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'log_source_permanently_deleted', { id: req.params.id });
  res.json({ status: 'permanently_deleted' });
});

router.post('/recycle-bin/sources/permanent-delete-bulk', async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { rows } = await pool.query(
    `DELETE FROM log_sources WHERE id = ANY($1::uuid[]) AND deleted_at IS NOT NULL RETURNING id`,
    [parsed.data.ids]
  );
  await recordAudit(req.user!.id, 'sources_bulk_permanently_deleted', { count: rows.length });
  res.json({ status: 'permanently_deleted', count: rows.length });
});

router.post('/recycle-bin/sources/empty', async (req, res) => {
  const { rows } = await pool.query(`DELETE FROM log_sources WHERE deleted_at IS NOT NULL RETURNING id`);
  await recordAudit(req.user!.id, 'sources_recycle_bin_emptied', { count: rows.length });
  res.json({ status: 'emptied', count: rows.length });
});

// POST /api/admin/recycle-bin/empty-all -> the master "Empty Recycle Bin"
// button: permanently deletes everything in every category at once.
router.post('/recycle-bin/empty-all', async (req, res) => {
  const [logsResult, alertsResult, sourcesResult] = await Promise.all([
    pool.query(`DELETE FROM logs WHERE deleted_at IS NOT NULL RETURNING id`),
    pool.query(`DELETE FROM alerts WHERE deleted_at IS NOT NULL RETURNING id`),
    pool.query(`DELETE FROM log_sources WHERE deleted_at IS NOT NULL RETURNING id`),
  ]);
  const { rows: deletedUsers } = await pool.query(`SELECT id FROM users WHERE deleted_at IS NOT NULL`);
  let accountsCount = 0;
  for (const row of deletedUsers) {
    if (await hardDeleteUser(row.id)) accountsCount++;
  }

  const summary = {
    logs: logsResult.rows.length,
    alerts: alertsResult.rows.length,
    sources: sourcesResult.rows.length,
    accounts: accountsCount,
  };
  await recordAudit(req.user!.id, 'recycle_bin_emptied_all', summary);
  res.json({ status: 'emptied', ...summary });
});

export default router;
