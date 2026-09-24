import express from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/role';
import { recordAudit } from '../services/audit';

const router = express.Router();
router.use(requireAuth);

// POST /api/access-requests -> a logged-in user asks to be approved for
// sensitive (unmasked) log access. One pending request per user at a time.
router.post('/', async (req, res) => {
  if (req.user!.sensitiveAccess) {
    return res.status(400).json({ error: 'You already have sensitive access.' });
  }

  const { rows: existing } = await pool.query(
    `SELECT id FROM access_requests WHERE user_id = $1 AND status = 'pending'`,
    [req.user!.id]
  );
  if (existing.length > 0) {
    return res.status(409).json({ error: 'You already have a pending request.' });
  }

  const { rows } = await pool.query(
    `INSERT INTO access_requests (user_id) VALUES ($1) RETURNING id, status, created_at`,
    [req.user!.id]
  );
  res.status(201).json(rows[0]);
});

// GET /api/access-requests (admin only) -> list all requests, newest first
router.get('/', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT ar.id, ar.status, ar.created_at, ar.resolved_at, u.id AS user_id, u.email
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
     WHERE id = $1 AND status = 'pending' RETURNING user_id`,
    [req.params.id]
  );
  const request = rows[0];
  if (!request) return res.status(404).json({ error: 'Request not found or already resolved.' });

  await pool.query(`UPDATE users SET sensitive_access = TRUE WHERE id = $1`, [request.user_id]);
  await recordAudit(req.user!.id, 'access_request_approved', { requestId: req.params.id });

  res.json({ status: 'approved' });
});

// POST /api/access-requests/:id/reject (admin only)
router.post('/:id/reject', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE access_requests SET status = 'rejected', resolved_at = now()
     WHERE id = $1 AND status = 'pending' RETURNING id`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Request not found or already resolved.' });

  await recordAudit(req.user!.id, 'access_request_rejected', { requestId: req.params.id });
  res.json({ status: 'rejected' });
});

export default router;
