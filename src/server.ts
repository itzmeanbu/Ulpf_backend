import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

// Express 4 does not catch errors thrown inside async route handlers, which
// leaves the request hanging forever. This small patch sends those errors to
// the error handler at the bottom of this file instead.
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Layer = require('express/lib/router/layer');
  Layer.prototype.handle_request = function handle(req: any, res: any, next: any) {
    const fn = this.handle;
    if (fn.length > 3) return next();
    try {
      const result = fn(req, res, next);
      if (result && typeof result.catch === 'function') result.catch(next);
    } catch (err) {
      next(err);
    }
  };
} catch (e: any) {
  console.warn('[ULPF] Async error patch not applied:', e.message);
}

import { initDb } from './db';
import authRoutes from './routes/auth';
import logRoutes from './routes/logs';
import alertRoutes from './routes/alerts';
import accessRequestRoutes from './routes/accessRequests';
import adminRoutes from './routes/admin';

const app = express();
app.set('trust proxy', 1);

// --- Security middleware ---
app.use(helmet());
const allowedOrigins = (process.env.FRONTEND_ORIGIN || 'http://localhost:3000,http://localhost:5173')
  .split(',')
  .map((o) => o.trim().replace(/\/+$/, ''))
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
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

// --- Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/access-requests', accessRequestRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
});

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

export default app;
