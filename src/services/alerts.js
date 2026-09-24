const { pool } = require('../db');

// NEW: reads the admin-configured AI/Detection settings out of the
// `settings` table. If nothing has been saved yet, everything defaults to
// "on" at medium sensitivity, matching the previous hardcoded behavior.
async function getAiSettings() {
  const { rows } = await pool.query(
    `SELECT value FROM settings WHERE key = 'ai_settings'`
  );
  const fallback = {
    anomalyDetection: true,
    threatCorrelation: true,
    aiMasking: false,
    automaticAlerts: true,
    sensitivity: 'medium',
  };
  if (!rows[0]) return fallback;
  try {
    return { ...fallback, ...JSON.parse(rows[0].value) };
  } catch {
    return fallback;
  }
}

// Sensitivity just moves the thresholds up/down. Low sensitivity = fewer,
// more confident alerts; high sensitivity = more alerts, sooner.
const FAILED_LOGIN_THRESHOLDS = { low: 8, medium: 5, high: 3 };
const CORRELATION_THRESHOLDS = { low: 5, medium: 3, high: 2 };

// Very simple deterministic rule: too many failed logins for the same
// email inside a short window -> raise an alert with a plain-language
// reason. Deliberately simple and explainable, as the spec asks for
// (reasons, not just an unexplained AI score).
async function checkFailedLogins(email) {
  const settings = await getAiSettings();
  if (!settings.anomalyDetection) return;

  const WINDOW_MINUTES = 5;
  const threshold = FAILED_LOGIN_THRESHOLDS[settings.sensitivity] || FAILED_LOGIN_THRESHOLDS.medium;

  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS count FROM login_attempts
     WHERE email = $1 AND success = FALSE
       AND created_at > now() - interval '${WINDOW_MINUTES} minutes'`,
    [email]
  );

  const count = rows[0].count;
  if (count >= threshold && settings.automaticAlerts) {
    await pool.query(
      `INSERT INTO alerts (reason, severity)
       VALUES ($1, 'high')`,
      [`${count} failed login attempts for ${email} in the last ${WINDOW_MINUTES} minutes.`]
    );
  }
}

// Placeholder for correlating related events from multiple sources.
// A prototype-level version: if several logs share the same sourceIP within
// a short time, flag it. Threshold now follows the admin sensitivity setting.
async function correlateEvent(newEventId, sourceIP) {
  if (!sourceIP) return;

  const settings = await getAiSettings();
  if (!settings.threatCorrelation) return;

  const threshold = CORRELATION_THRESHOLDS[settings.sensitivity] || CORRELATION_THRESHOLDS.medium;

  const { rows } = await pool.query(
    `SELECT id FROM logs
     WHERE source_ip = $1 AND id != $2
       AND created_at > now() - interval '10 minutes'`,
    [sourceIP, newEventId]
  );

  if (rows.length >= threshold && settings.automaticAlerts) {
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

module.exports = { checkFailedLogins, correlateEvent, getAiSettings };
