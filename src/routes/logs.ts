import express from 'express';
import argon2 from 'argon2';
import { z } from 'zod';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/role';
import { normalizeRawLog } from '../services/normalize';
import { maskNormalizedEvent, DEFAULT_MASKING_CONFIG } from '../utils/masking';
import { encryptObject, decryptObject } from '../utils/crypto';
import { correlateEvent } from '../services/alerts';
import { recordAudit } from '../services/audit';
import { buildReadableSummary } from '../services/humanize';
import { MaskingConfig } from '../types';

const router = express.Router();
router.use(requireAuth);

// Only analysts and admins may upload, delete or restore logs. Viewers (and
// pending accounts, which never reach here) are read-only. A viewer who wants
// to upload asks an admin (POST /api/access-requests { type: 'upload' }); when
// the admin approves, the viewer becomes an analyst.
const canManage = requireRole('analyst', 'admin');
const canUpload = requireRole('analyst', 'admin');

// Ownership rule: an admin may touch ANY log; an analyst only logs they
// uploaded themselves. Every delete / restore query below uses this pair:
//   ($N::boolean OR uploaded_by = $M)  with  [isAdmin(req), req.user.id]
function isAdmin(req: express.Request): boolean {
  return req.user!.role === 'admin';
}

async function getMaskingConfig(): Promise<MaskingConfig> {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'masking_fields'`);
  if (!rows[0]) return DEFAULT_MASKING_CONFIG;
  try {
    return { ...DEFAULT_MASKING_CONFIG, ...JSON.parse(rows[0].value) };
  } catch {
    return DEFAULT_MASKING_CONFIG;
  }
}

function maskedView(log: any, config: MaskingConfig, viewer?: { id: string; role: string }): any {
  const masked = maskNormalizedEvent({ ...log.masked_json }, config);
  const view: any = {
    ...masked,
    eventId: log.id,
    readableSummary: buildReadableSummary(masked),
    deletedAt: log.deleted_at || null,
  };
  // When we know who is looking, tell the frontend which logs are theirs and
  // which ones they may delete, so it can show/hide the delete buttons.
  if (viewer) {
    const mine = !!log.uploaded_by && log.uploaded_by === viewer.id;
    view.uploadedBy = log.uploaded_by || null;
    view.isMine = mine;
    view.canDelete = viewer.role === 'admin' || (viewer.role === 'analyst' && mine);
    // Only the admin is shown WHO uploaded a log.
    if (viewer.role === 'admin') view.uploadedByEmail = log.uploaded_by_email || null;
  }
  return view;
}

const uploadSchema = z.object({
  rawLog: z.string().min(1, 'rawLog is required.'),
  sourceType: z.string().optional(),
});

// POST /api/logs/upload  { rawLog, sourceType } -> parsed result + readable summary
router.post('/upload', canUpload, async (req, res) => {
  const parsed = uploadSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { rawLog, sourceType } = parsed.data;

  let normalized;
  try {
    ({ normalized } = normalizeRawLog(rawLog, sourceType));
  } catch (err: any) {
    return res.status(err.status || 422).json({ error: err.message });
  }

  const maskingConfig = await getMaskingConfig();
  const masked = maskNormalizedEvent(normalized, maskingConfig);
  const { blob, iv, tag } = encryptObject({ ...normalized, rawLog, masked: false });

  const { rows } = await pool.query(
    `INSERT INTO logs
      (vendor, event_type, source_type, timestamp, source_ip, dest_ip, action,
       protocol, raw_log, masked_json, encrypted_blob, encrypted_iv, encrypted_tag, uploaded_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING id`,
    [
      normalized.vendor,
      normalized.eventType,
      normalized.sourceType,
      normalized.timestamp,
      normalized.sourceIP,
      normalized.destIP,
      normalized.action,
      normalized.protocol,
      rawLog,
      masked,
      blob,
      iv,
      tag,
      req.user!.id,
    ]
  );

  const eventId = rows[0].id;
  await correlateEvent(eventId, normalized.sourceIP);
  await recordAudit(req.user!.id, 'log_upload', { eventId });

  res.status(201).json({
    eventId,
    status: 'processed',
    ...masked,
    readableSummary: buildReadableSummary(masked),
  });
});

// GET /api/logs/search?query=...&scope=mine|all  -> array of masked events
//   scope=mine -> only logs the caller uploaded
//   scope=all  -> every log (default)
// Deleted logs are never shown.
// IMPORTANT: registered BEFORE /:eventId so Express doesn't treat "search" as an id.
router.get('/search', async (req, res) => {
  const query = (req.query.query || '').toString();
  const scope = req.query.scope === 'mine' ? 'mine' : 'all';
  const maskingConfig = await getMaskingConfig();

  const params: any[] = [`%${query}%`];
  let ownerClause = '';
  if (scope === 'mine') {
    params.push(req.user!.id);
    ownerClause = 'AND l.uploaded_by = $2';
  }

  const { rows } = await pool.query(
    `SELECT l.*, u.email AS uploaded_by_email
     FROM logs l LEFT JOIN users u ON u.id = l.uploaded_by
     WHERE l.deleted_at IS NULL
       AND (l.vendor ILIKE $1 OR l.event_type ILIKE $1 OR l.action ILIKE $1
        OR l.source_ip ILIKE $1 OR l.dest_ip ILIKE $1)
       ${ownerClause}
     ORDER BY l.created_at DESC
     LIMIT 200`,
    params
  );

  res.json(rows.map((log: any) => maskedView(log, maskingConfig, req.user!)));
});

// GET /api/logs/stats -> dashboard summary numbers (deleted logs excluded)
router.get('/stats', async (req, res, next) => {
  try {
    const { rows: totalRows } = await pool.query(`SELECT COUNT(*)::int AS count FROM logs WHERE deleted_at IS NULL`);
    const { rows: sourceRows } = await pool.query(
      `SELECT DISTINCT source_type FROM logs WHERE source_type IS NOT NULL AND deleted_at IS NULL`
    );
    const { rows: recentRows } = await pool.query(
      `SELECT * FROM logs WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 5`
    );

    const maskingConfig = await getMaskingConfig();
    res.json({
      total: totalRows[0].count,
      critical: 0,
      sources: sourceRows.map((r: any) => r.source_type),
      recentEvents: recentRows.map((log: any) => maskedView(log, maskingConfig)),
    });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ */
/* RECYCLE BIN — every log a user deletes lands here first. Nothing is */
/* actually gone until it is permanently deleted (or emptied) from here. */
/* ------------------------------------------------------------------ */

// GET /api/logs/recycle-bin -> every soft-deleted log, newest-deleted first
router.get('/recycle-bin', canManage, async (req, res) => {
  const maskingConfig = await getMaskingConfig();
  const { rows } = await pool.query(
    `SELECT l.*, u.email AS deleted_by_email
     FROM logs l LEFT JOIN users u ON u.id = l.deleted_by
     WHERE l.deleted_at IS NOT NULL
       AND ($1::boolean OR l.uploaded_by = $2)
     ORDER BY l.deleted_at DESC
     LIMIT 500`,
    [isAdmin(req), req.user!.id]
  );
  res.json(
    rows.map((log: any) => ({ ...maskedView(log, maskingConfig), deletedByEmail: log.deleted_by_email }))
  );
});

const idsSchema = z.object({ ids: z.array(z.string()).min(1, 'No items selected.') });

// POST /api/logs/bulk-delete  { ids } -> moves many logs to the recycle bin
// (this is what "select all" + "delete selected" calls on the Logs page)
router.post('/bulk-delete', canManage, async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });

  const { rows } = await pool.query(
    `UPDATE logs SET deleted_at = now(), deleted_by = $1
     WHERE id = ANY($2::uuid[]) AND deleted_at IS NULL
       AND ($3::boolean OR uploaded_by = $1) RETURNING id`,
    [req.user!.id, parsed.data.ids, isAdmin(req)]
  );
  await recordAudit(req.user!.id, 'logs_bulk_deleted', { count: rows.length, ids: rows.map((r: any) => r.id) });
  // "skipped" = selected logs the caller is not allowed to delete (not theirs).
  res.json({ status: 'deleted', count: rows.length, skipped: parsed.data.ids.length - rows.length });
});

// POST /api/logs/clear-all -> moves logs to the recycle bin in one go.
//   admin   -> every remaining log
//   analyst -> only the logs THEY uploaded
router.post('/clear-all', canManage, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE logs SET deleted_at = now(), deleted_by = $1
     WHERE deleted_at IS NULL AND ($2::boolean OR uploaded_by = $1) RETURNING id`,
    [req.user!.id, isAdmin(req)]
  );
  await recordAudit(req.user!.id, 'logs_cleared_all', { count: rows.length });
  res.json({ status: 'deleted', count: rows.length });
});

// POST /api/logs/recycle-bin/restore-bulk  { ids } -> pulls many logs back out
router.post('/recycle-bin/restore-bulk', canManage, async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });

  const { rows } = await pool.query(
    `UPDATE logs SET deleted_at = NULL, deleted_by = NULL
     WHERE id = ANY($1::uuid[]) AND deleted_at IS NOT NULL
       AND ($2::boolean OR uploaded_by = $3) RETURNING id`,
    [parsed.data.ids, isAdmin(req), req.user!.id]
  );
  await recordAudit(req.user!.id, 'logs_bulk_restored', { count: rows.length, ids: rows.map((r: any) => r.id) });
  res.json({ status: 'restored', count: rows.length });
});

// POST /api/logs/recycle-bin/permanent-delete-bulk  { ids } -> select-all + delete forever
router.post('/recycle-bin/permanent-delete-bulk', canManage, async (req, res) => {
  const parsed = idsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });

  const { rows } = await pool.query(
    `DELETE FROM logs WHERE id = ANY($1::uuid[]) AND deleted_at IS NOT NULL
       AND ($2::boolean OR uploaded_by = $3) RETURNING id`,
    [parsed.data.ids, isAdmin(req), req.user!.id]
  );
  await recordAudit(req.user!.id, 'logs_bulk_permanently_deleted', { count: rows.length });
  res.json({ status: 'permanently_deleted', count: rows.length });
});

// POST /api/logs/recycle-bin/empty -> empty the WHOLE logs recycle bin at once
router.post('/recycle-bin/empty', canManage, async (req, res) => {
  const { rows } = await pool.query(
    `DELETE FROM logs WHERE deleted_at IS NOT NULL
       AND ($1::boolean OR uploaded_by = $2) RETURNING id`,
    [isAdmin(req), req.user!.id]
  );
  await recordAudit(req.user!.id, 'logs_recycle_bin_emptied', { count: rows.length });
  res.json({ status: 'emptied', count: rows.length });
});

// POST /api/logs/recycle-bin/:eventId/restore -> restore a single log
router.post('/recycle-bin/:eventId/restore', canManage, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE logs SET deleted_at = NULL, deleted_by = NULL
     WHERE id = $1 AND deleted_at IS NOT NULL
       AND ($2::boolean OR uploaded_by = $3) RETURNING id`,
    [req.params.eventId, isAdmin(req), req.user!.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Log not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'log_restored', { eventId: req.params.eventId });
  res.json({ status: 'restored' });
});

// DELETE /api/logs/recycle-bin/:eventId -> permanently delete one log
router.delete('/recycle-bin/:eventId', canManage, async (req, res) => {
  const { rows } = await pool.query(
    `DELETE FROM logs WHERE id = $1 AND deleted_at IS NOT NULL
       AND ($2::boolean OR uploaded_by = $3) RETURNING id`,
    [req.params.eventId, isAdmin(req), req.user!.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Log not found in the recycle bin.' });
  await recordAudit(req.user!.id, 'log_permanently_deleted', { eventId: req.params.eventId });
  res.json({ status: 'permanently_deleted' });
});

// DELETE /api/logs/:eventId -> moves a single log to the recycle bin (soft delete).
// Admin: any log. Analyst: only their own uploads.
// IMPORTANT: registered AFTER the /recycle-bin/* routes above, same ordering
// reason as /search and /stats.
router.delete('/:eventId', canManage, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE logs SET deleted_at = now(), deleted_by = $1
     WHERE id = $2 AND deleted_at IS NULL
       AND ($3::boolean OR uploaded_by = $1) RETURNING id`,
    [req.user!.id, req.params.eventId, isAdmin(req)]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Log not found, or it is not one of your uploads.' });
  await recordAudit(req.user!.id, 'log_deleted', { eventId: req.params.eventId });
  res.json({ status: 'deleted' });
});

// GET /api/logs/:eventId -> masked normalized event (any logged-in user)
router.get('/:eventId', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM logs WHERE id = $1`, [req.params.eventId]);
  const log = rows[0];
  if (!log) return res.status(404).json({ error: 'Log not found.' });

  res.json(maskedView(log, await getMaskingConfig()));
});

const unlockSchema = z.object({
  secondaryPassword: z.string().min(1, 'secondaryPassword is required.'),
});

// POST /api/logs/:eventId/unlock  { secondaryPassword } -> unmasked event
router.post('/:eventId/unlock', async (req, res) => {
  if (!req.user!.sensitiveAccess) {
    return res.status(403).json({ error: 'You are not approved for sensitive log access.' });
  }

  const parsed = unlockSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }

  const { rows: settingRows } = await pool.query(
    `SELECT value FROM settings WHERE key = 'secondary_password_hash'`
  );
  const secondaryHash = settingRows[0]?.value;
  const passwordOk = secondaryHash
    ? await argon2.verify(secondaryHash, parsed.data.secondaryPassword)
    : false;

  if (!passwordOk) {
    return res.status(403).json({ error: 'Incorrect secondary password.' });
  }

  const { rows } = await pool.query(`SELECT * FROM logs WHERE id = $1`, [req.params.eventId]);
  const log = rows[0];
  if (!log) return res.status(404).json({ error: 'Log not found.' });

  const decrypted = decryptObject({
    blob: log.encrypted_blob,
    iv: log.encrypted_iv,
    tag: log.encrypted_tag,
  });

  await recordAudit(req.user!.id, 'log_unlock', { eventId: log.id });

  res.json({
    ...decrypted,
    eventId: log.id,
    masked: false,
    readableSummary: buildReadableSummary(decrypted),
  });
});

export default router;
