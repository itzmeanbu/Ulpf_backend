const { Pool } = require('pg');
const argon2 = require('argon2');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Creates every table ULPF needs if they don't already exist, then makes
// sure there is at least one admin user and one secondary unlock password
// so the app is usable on first run.
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'pending', -- pending | viewer | analyst | admin
      sensitive_access BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      vendor TEXT,
      event_type TEXT,
      source_type TEXT,
      timestamp TIMESTAMPTZ,
      source_ip TEXT,
      dest_ip TEXT,
      action TEXT,
      protocol TEXT,
      raw_log TEXT NOT NULL,
      masked_json JSONB NOT NULL,
      encrypted_blob TEXT NOT NULL,
      encrypted_iv TEXT NOT NULL,
      encrypted_tag TEXT NOT NULL,
      uploaded_by UUID REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      reason TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium', -- low | medium | high
      related_events UUID[] DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'open', -- open | investigating | resolved
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS access_requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id),
      status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      resolved_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id),
      action TEXT NOT NULL,
      details JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL,
      success BOOLEAN NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    -- NEW: lets an admin turn a user's login on/off without changing their role.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT FALSE;

    -- NEW: the list of ingestion sources shown/managed on the admin "Log Sources" screen.
    CREATE TABLE IF NOT EXISTS log_sources (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT UNIQUE NOT NULL,
      vendor TEXT,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    -- NEW: which log categories (source names) a given user is allowed to see,
    -- for the admin "Log Access" screen. A row present = that user can see that category.
    CREATE TABLE IF NOT EXISTS user_log_access (
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      PRIMARY KEY (user_id, category)
    );
  `);

  // Enable gen_random_uuid() (pgcrypto) - safe no-op if already enabled.
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`).catch(() => {});


// BOOTSTRAP_ADMIN_PASSWORD in Render and restarting always takes effect.
const email = (process.env.BOOTSTRAP_ADMIN_EMAIL || '').trim().toLowerCase();
const password = (process.env.BOOTSTRAP_ADMIN_PASSWORD || '').trim();
if (email && password) {
  const hash = await argon2.hash(password, { type: argon2.argon2id });
  await pool.query(
    `INSERT INTO users (email, password_hash, role, sensitive_access)
     VALUES ($1, $2, 'admin', TRUE)
     ON CONFLICT (email) DO UPDATE
     SET password_hash = EXCLUDED.password_hash, role = 'admin', sensitive_access = TRUE`,
    [email, hash]
  );
  // Only ONE admin may exist: whoever the environment variables name.
  // If the admin email is changed in Render, the old admin becomes a viewer.
  await pool.query(`UPDATE users SET disabled = FALSE WHERE email = $1`, [email]);
  await pool.query(`UPDATE users SET role = 'viewer' WHERE role = 'admin' AND email <> $1`, [email]);
  console.log(`[ULPF] Bootstrap admin ensured/synced: ${email}`);
}

  // Bootstrap the secondary unlock password if not set yet.
  const { rows: setting } = await pool.query(
    `SELECT value FROM settings WHERE key = 'secondary_password_hash'`
  );
  if (setting.length === 0 && process.env.BOOTSTRAP_SECONDARY_PASSWORD) {
    const hash = await argon2.hash(process.env.BOOTSTRAP_SECONDARY_PASSWORD, {
      type: argon2.argon2id,
    });
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ('secondary_password_hash', $1)
       ON CONFLICT (key) DO NOTHING`,
      [hash]
    );
    console.log('[ULPF] Bootstrap secondary unlock password ensured.');
  }

  // NEW: seed sensible defaults for the admin config screens, so the pages
  // have something real to show the very first time an admin opens them.
  const defaultSettings = {
    masking_fields: JSON.stringify({
      email: true,
      password: true,
      apiKey: true,
      phone: true,
      ip: true,
    }),
    ai_settings: JSON.stringify({
      anomalyDetection: true,
      threatCorrelation: true,
      aiMasking: false,
      automaticAlerts: true,
      sensitivity: 'medium',
    }),
    system_settings: JSON.stringify({
      logRetentionDays: 90,
      maxUploadSizeMb: 2,
      sessionTimeoutMinutes: 480,
      notifyOnCriticalAlerts: true,
    }),
  };
  for (const [key, value] of Object.entries(defaultSettings)) {
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
      [key, value]
    );
  }

  // NEW: seed a few common ingestion sources if none exist yet.
  const { rows: sources } = await pool.query(`SELECT id FROM log_sources LIMIT 1`);
  if (sources.length === 0) {
    const defaults = [
      ['Cisco', 'Cisco'],
      ['Fortinet', 'Fortinet'],
      ['Linux', 'Linux'],
      ['Windows', 'Windows'],
    ];
    for (const [name, vendor] of defaults) {
      await pool.query(
        `INSERT INTO log_sources (name, vendor) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`,
        [name, vendor]
      );
    }
  }
}

module.exports = { pool, initDb };
