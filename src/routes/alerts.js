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

module.exports = router;
