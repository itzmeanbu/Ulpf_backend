import { pool } from '../db';

async function getAiSettings(): Promise<any> {
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

const FAILED_LOGIN_THRESHOLDS: Record<string, number> = { low: 8, medium: 5, high: 3 };
const CORRELATION_THRESHOLDS: Record<string, number> = { low: 5, medium: 3, high: 2 };

export async function checkFailedLogins(email: string): Promise<void> {
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

export async function correlateEvent(newEventId: string, sourceIP: string | null | undefined): Promise<void> {
  if (!sourceIP) return;

  const settings = await getAiSettings();
  if (!settings.threatCorrelation) return;

  const threshold = CORRELATION_THRESHOLDS[settings.sensitivity] || CORRELATION_THRESHOLDS.medium;

  const { rows } = await pool.query(
    `SELECT id FROM logs
     WHERE source_ip = $1 AND id != $2
       AND deleted_at IS NULL
       AND created_at > now() - interval '10 minutes'`,
    [sourceIP, newEventId]
  );

  if (rows.length >= threshold && settings.automaticAlerts) {
    const relatedIds = rows.map((r: any) => r.id).concat(newEventId);
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

export { getAiSettings };
