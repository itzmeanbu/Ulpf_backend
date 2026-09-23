require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

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
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173',
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

// --- Error handler (keeps error shape consistent: { error: "..." }) ---
app.use((err, req, res, next) => {
  console.error(err);
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
