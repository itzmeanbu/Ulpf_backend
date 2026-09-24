import { pool } from '../db';

// Records important actions: approvals, unlocks, admin changes, deletes,
// restores, etc.
export async function recordAudit(userId: string | null | undefined, action: string, details: Record<string, any> = {}): Promise<void> {
  await pool.query(
    `INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)`,
    [userId || null, action, details]
  );
}
