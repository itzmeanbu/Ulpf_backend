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
      status TEXT NOT NULL DEFAULT 'open', -- open | reviewed | dismissed
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
  `);

  // Enable gen_random_uuid() (pgcrypto) - safe no-op if already enabled.
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`).catch(() => {});

  // Bootstrap first admin if none exists yet.
  const { rows: admins } = await pool.query(
    `SELECT id FROM users WHERE role = 'admin' LIMIT 1`
  );
  if (admins.length === 0) {
    const email = process.env.BOOTSTRAP_ADMIN_EMAIL;
    const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
    if (email && password) {
      const hash = await argon2.hash(password, { type: argon2.argon2id });
      await pool.query(
        `INSERT INTO users (email, password_hash, role, sensitive_access)
         VALUES ($1, $2, 'admin', TRUE)
         ON CONFLICT (email) DO NOTHING`,
        [email, hash]
      );
      console.log(`[ULPF] Bootstrap admin ensured: ${email}`);
    }
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
}

module.exports = { pool, initDb };
