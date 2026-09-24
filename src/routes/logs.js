const express = require('express');
const argon2 = require('argon2');
const { z } = require('zod');
const { pool } = require('../db');
const { requireAuth } = require('../middleware/auth');
const { normalizeRawLog } = require('../services/normalize');
const { maskNormalizedEvent, DEFAULT_MASKING_CONFIG } = require('../utils/masking');
const { encryptObject, decryptObject } = require('../utils/crypto');
const { correlateEvent } = require('../services/alerts');
const { recordAudit } = require('../services/audit');
const { buildReadableSummary } = require('../services/humanize');

const router = express.Router();
router.use(requireAuth);

// NEW: reads the admin-configured Masking Rules (email/password/apiKey/phone/ip
// on or off) so uploads respect whatever the admin last saved.
async function getMaskingConfig() {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'masking_fields'`);
  if (!rows[0]) return DEFAULT_MASKING_CONFIG;
  try {
    return { ...DEFAULT_MASKING_CONFIG, ...JSON.parse(rows[0].value) };
  } catch {
    return DEFAULT_MASKING_CONFIG;
  }
}

// Applies the current masking rules every time a log is shown. This means
// logs uploaded earlier are protected too, and rule changes apply at once.
function maskedView(log, config) {
  const masked = maskNormalizedEvent({ ...log.masked_json }, config);
  return { ...masked, eventId: log.id, readableSummary: buildReadableSummary(masked) };
}

const uploadSchema = z.object({
  rawLog: z.string().min(1, 'rawLog is required.'),
  sourceType: z.string().optional(),
});

// POST /api/logs/upload  { rawLog, sourceType } -> { eventId, status }
router.post('/upload', async (req, res) => {
  const parsed = uploadSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { rawLog, sourceType } = parsed.data;

  let normalized;
  try {
    ({ normalized } = normalizeRawLog(rawLog, sourceType));
  } catch (err) {
    return res.status(err.status || 422).json({ error: err.message });
  }

  const maskingConfig = await getMaskingConfig();
  const masked = maskNormalizedEvent(normalized, maskingConfig);
  // The sensitive/full version (including the raw log) is what actually
  // gets AES-256-GCM encrypted before it touches the database.
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
      req.user.id,
    ]
  );

  const eventId = rows[0].id;
  await correlateEvent(eventId, normalized.sourceIP);
  await recordAudit(req.user.id, 'log_upload', { eventId });

  res.status(201).json({ eventId, status: 'processed' });
});

// GET /api/logs/search?query=...  -> array of masked events
// IMPORTANT: this is registered BEFORE /:eventId so Express doesn't treat
// the literal word "search" as an eventId value.
router.get('/search', async (req, res) => {
  const query = (req.query.query || '').toString();
  const maskingConfig = await getMaskingConfig();

  const { rows } = await pool.query(
    `SELECT * FROM logs
     WHERE vendor ILIKE $1 OR event_type ILIKE $1 OR action ILIKE $1
        OR source_ip ILIKE $1 OR dest_ip ILIKE $1
     ORDER BY created_at DESC
     LIMIT 100`,
    [`%${query}%`]
  );

  res.json(rows.map((log) => maskedView(log, maskingConfig)));
});

// GET /api/logs/stats -> dashboard summary numbers
// IMPORTANT: this must be registered BEFORE /:eventId, same reason as /search
// above - otherwise "stats" gets treated as an eventId and crashes the query.
router.get('/stats', async (req, res, next) => {
  try {
    const { rows: totalRows } = await pool.query(`SELECT COUNT(*)::int AS count FROM logs`);
    const { rows: sourceRows } = await pool.query(
      `SELECT DISTINCT source_type FROM logs WHERE source_type IS NOT NULL`
    );
    const { rows: recentRows } = await pool.query(
      `SELECT * FROM logs ORDER BY created_at DESC LIMIT 5`
    );

    const maskingConfig = await getMaskingConfig();
    res.json({
      total: totalRows[0].count,
      critical: 0, // TODO: decide what "critical" means for a log row, wire this up
      sources: sourceRows.map((r) => r.source_type),
      recentEvents: recentRows.map((log) => maskedView(log, maskingConfig)),
    });
  } catch (err) {
    next(err);
  }
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
// Only succeeds if BOTH are true:
//  1. the logged-in user has been admin-approved for sensitive access
//  2. the secondaryPassword matches the one shared unlock code
router.post('/:eventId/unlock', async (req, res) => {
  if (!req.user.sensitiveAccess) {
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

  await recordAudit(req.user.id, 'log_unlock', { eventId: log.id });

  res.json({
    ...decrypted,
    eventId: log.id,
    masked: false,
    readableSummary: buildReadableSummary(decrypted),
  });
});

module.exports = router;
