const { pool } = require('../db');

// Very simple deterministic rule: too many failed logins for the same
// email inside a short window -> raise an alert with a plain-language
// reason. Deliberately simple and explainable, as the spec asks for
// (reasons, not just an unexplained AI score).
async function checkFailedLogins(email) {
  const WINDOW_MINUTES = 5;
  const THRESHOLD = 5;

  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS count FROM login_attempts
     WHERE email = $1 AND success = FALSE
       AND created_at > now() - interval '${WINDOW_MINUTES} minutes'`,
    [email]
  );

  const count = rows[0].count;
  if (count >= THRESHOLD) {
    await pool.query(
      `INSERT INTO alerts (reason, severity)
       VALUES ($1, 'high')`,
      [`${count} failed login attempts for ${email} in the last ${WINDOW_MINUTES} minutes.`]
    );
  }
}

// Placeholder for correlating related events from multiple sources.
// A prototype-level version: if two logs share the same sourceIP within
// a short time and one is an "action" like a login failure, flag it.
async function correlateEvent(newEventId, sourceIP) {
  if (!sourceIP) return;

  const { rows } = await pool.query(
    `SELECT id FROM logs
     WHERE source_ip = $1 AND id != $2
       AND created_at > now() - interval '10 minutes'`,
    [sourceIP, newEventId]
  );

  if (rows.length >= 3) {
    const relatedIds = rows.map((r) => r.id).concat(newEventId);
    await pool.query(
      `INSERT INTO alerts (reason, severity, related_events)
       VALUES ($1, 'medium', $2)`,
      [
        `${rows.length + 1} related events observed from the same source IP within 10 minutes.`,
        relatedIds,
      ]
    );
  }
}

module.exports = { checkFailedLogins, correlateEvent };
