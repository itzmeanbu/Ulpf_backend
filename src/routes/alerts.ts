import express from 'express';
import { pool } from '../db';
import { requireAuth } from '../middleware/auth';

const router = express.Router();
router.use(requireAuth);

// GET /api/alerts -> array of { alertId, reason, severity, relatedEvents, status }
router.get('/', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM alerts WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 200`
  );

  res.json(
    rows.map((a: any) => ({
      alertId: a.id,
      reason: a.reason,
      severity: a.severity,
      relatedEvents: a.related_events,
      status: a.status,
      createdAt: a.created_at,
    }))
  );
});

// GET /api/alerts/summary -> counts for the dashboard cards
router.get('/summary', async (req, res, next) => {
  try {
    const { rows } = await pool.query(`SELECT severity, status FROM alerts WHERE deleted_at IS NULL`);
    res.json({
      active: rows.filter((a: any) => a.status !== 'resolved').length,
      critical: rows.filter((a: any) => a.severity === 'high').length,
      warning: rows.filter((a: any) => a.severity === 'medium').length,
      info: rows.filter((a: any) => a.severity === 'low').length,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
