const { pool } = require('../db');

// Records important actions: approvals, unlocks, admin changes, etc.
async function recordAudit(userId, action, details = {}) {
  await pool.query(
    `INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)`,
    [userId || null, action, details]
  );
}

module.exports = { recordAudit };
