const jwt = require('jsonwebtoken');
const { pool } = require('../db');

// Checks "Authorization: Bearer <token>", verifies it, then looks the user up
// in the database on every request. That way an admin's changes (approve,
// disable, change role, revoke sensitive access) take effect immediately,
// without the user having to log out and back in.
// Attaches { id, email, role, sensitiveAccess } to req.user.
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header.' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, email, role, sensitive_access, disabled FROM users WHERE id = $1`,
      [payload.id]
    );
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Account no longer exists.' });
    }
    if (user.disabled) {
      return res.status(403).json({ error: 'This account has been disabled.' });
    }
    if (user.role === 'pending') {
      return res.status(403).json({ error: 'Your account is awaiting admin approval.' });
    }

    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      sensitiveAccess: user.sensitive_access,
    };
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { requireAuth };
