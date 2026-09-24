const express = require('express');
const { pool } = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

// GET /api/alerts -> array of { alertId, reason, severity, relatedEvents, status }
router.get('/', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200`
  );

  res.json(
    rows.map((a) => ({
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
    const { rows } = await pool.query(`SELECT severity, status FROM alerts`);
    res.json({
      active: rows.filter((a) => a.status !== 'resolved').length,
      critical: rows.filter((a) => a.severity === 'high').length,
      warning: rows.filter((a) => a.severity === 'medium').length,
      info: rows.filter((a) => a.severity === 'low').length,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
