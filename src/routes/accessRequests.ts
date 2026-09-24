import express from 'express';
import { z } from 'zod';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/role';
import { recordAudit } from '../services/audit';

const router = express.Router();
router.use(requireAuth);

// Two kinds of request:
//   sensitive -> "let me see unmasked (sensitive) log details"
//   upload    -> "let me upload logs" (only viewers need this; approval makes
//                the viewer an analyst)
const createSchema = z.object({
  type: z.enum(['sensitive', 'upload']).default('sensitive'),
});

// POST /api/access-requests  { type? } -> a logged-in user asks an admin for access.
// One pending request per user per type at a time.
router.post('/', async (req, res) => {
  const parsed = createSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request type.' });
  const { type } = parsed.data;

  if (type === 'sensitive' && req.user!.sensitiveAccess) {
    return res.status(400).json({ error: 'You already have sensitive access.' });
  }
  if (type === 'upload' && (req.user!.role === 'analyst' || req.user!.role === 'admin')) {
    return res.status(400).json({ error: 'You can already upload logs.' });
  }

  const { rows: existing } = await pool.query(
    `SELECT id FROM access_requests WHERE user_id = $1 AND status = 'pending' AND type = $2`,
    [req.user!.id, type]
  );
  if (existing.length > 0) {
    return res.status(409).json({ error: 'You already have a pending request.' });
  }

  const { rows } = await pool.query(
    `INSERT INTO access_requests (user_id, type) VALUES ($1, $2) RETURNING id, type, status, created_at`,
    [req.user!.id, type]
  );
  await recordAudit(req.user!.id, 'access_request_created', { requestId: rows[0].id, type });
  res.status(201).json(rows[0]);
});

// GET /api/access-requests/mine -> the caller's own requests, newest first
// (so the page can say "waiting for admin approval" / "rejected").
router.get('/mine', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, type, status, created_at, resolved_at
     FROM access_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
    [req.user!.id]
  );
  res.json(rows);
});

// GET /api/access-requests (admin only) -> list all requests, newest first
router.get('/', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT ar.id, ar.type, ar.status, ar.created_at, ar.resolved_at, u.id AS user_id, u.email
     FROM access_requests ar
     JOIN users u ON u.id = ar.user_id
     WHERE u.deleted_at IS NULL
     ORDER BY ar.created_at DESC`
  );
  res.json(rows);
});

// POST /api/access-requests/:id/approve (admin only)
router.post('/:id/approve', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE access_requests SET status = 'approved', resolved_at = now()
     WHERE id = $1 AND status = 'pending' RETURNING user_id, type`,
    [req.params.id]
  );
  const request = rows[0];
  if (!request) return res.status(404).json({ error: 'Request not found or already resolved.' });

  if (request.type === 'upload') {
    // Only promote viewers: never touch an admin, and never demote or
    // re-activate a pending account.
    await pool.query(`UPDATE users SET role = 'analyst' WHERE id = $1 AND role = 'viewer'`, [request.user_id]);
  } else {
    await pool.query(`UPDATE users SET sensitive_access = TRUE WHERE id = $1`, [request.user_id]);
  }
  await recordAudit(req.user!.id, 'access_request_approved', { requestId: req.params.id, type: request.type });

  res.json({ status: 'approved' });
});

// POST /api/access-requests/:id/reject (admin only)
router.post('/:id/reject', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE access_requests SET status = 'rejected', resolved_at = now()
     WHERE id = $1 AND status = 'pending' RETURNING id, type`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Request not found or already resolved.' });

  await recordAudit(req.user!.id, 'access_request_rejected', { requestId: req.params.id, type: rows[0].type });
  res.json({ status: 'rejected' });
});

export default router;
