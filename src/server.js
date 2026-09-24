require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// Express 4 does not catch errors thrown inside async route handlers, which
// leaves the request hanging forever. This small patch sends those errors to
// the error handler at the bottom of this file instead.
try {
  const Layer = require('express/lib/router/layer');
  Layer.prototype.handle_request = function handle(req, res, next) {
    const fn = this.handle;
    if (fn.length > 3) return next();
    try {
      const result = fn(req, res, next);
      if (result && typeof result.catch === 'function') result.catch(next);
    } catch (err) {
      next(err);
    }
  };
} catch (e) {
  console.warn('[ULPF] Async error patch not applied:', e.message);
}

const { initDb } = require('./db');
const authRoutes = require('./routes/auth');
const logRoutes = require('./routes/logs');
const alertRoutes = require('./routes/alerts');
const accessRequestRoutes = require('./routes/accessRequests');
const adminRoutes = require('./routes/admin');

const app = express();
app.set('trust proxy', 1);

// --- Security middleware (spec section 12) ---
app.use(helmet());
// FRONTEND_ORIGIN can hold one address or several separated by commas,
// e.g. https://my-app.vercel.app,http://localhost:3000
// A trailing "/" is ignored so a small typo cannot block every request.
const allowedOrigins = (process.env.FRONTEND_ORIGIN || 'http://localhost:3000,http://localhost:5173')
  .split(',')
  .map((o) => o.trim().replace(/\/+$/, ''))
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // No origin = server-to-server or curl request; allow it.
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
  })
);
app.use(express.json({ limit: '2mb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' },
});
app.use('/api/auth', authLimiter);

// --- Routes (must match the shared frontend/backend API contract) ---
app.use('/api/auth', authRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/access-requests', accessRequestRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Unknown /api address -> clear JSON message instead of an HTML page
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// --- Error handler (keeps error shape consistent: { error: "..." }) ---
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
});

// Safety net: an uncaught error in any route (like the /logs/stats bug we
// just fixed) should not be able to take the whole server down.
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection (server stayed up):', err);
});

const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`[ULPF] Backend running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('[ULPF] Failed to initialize database:', err);
    process.exit(1);
  });

module.exports = app;
