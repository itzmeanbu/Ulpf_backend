# ULPF Backend

Backend-only implementation of the Universal Log Pre-processing Framework.
No frontend code lives here — this is built to the locked API contract so
a separate frontend can be built and swapped in independently.

## 1. Install

```bash
npm install
```

## 2. Set up PostgreSQL

Create a database, then copy the env file:

```bash
cp .env.example .env
```

Fill in `.env`:
- `DATABASE_URL` — your Postgres connection string
- `JWT_SECRET` — any long random string
- `AES_MASTER_KEY_HEX` — generate one with:
  ```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  ```
  Paste the output in. This key is never stored anywhere except this
  environment variable — not in code, not in the database, not sent to
  the frontend.
- `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` — the first admin
  account, created automatically the first time the server starts if no
  admin exists yet.
- `BOOTSTRAP_SECONDARY_PASSWORD` — the starting shared "unlock" code
  needed to view unmasked sensitive logs. Change it later from the admin
  panel (`POST /api/admin/secondary-password`).

## 3. Run

```bash
npm start
```

Tables are created automatically on first run (see `src/db.js`). You'll
see a log line confirming the bootstrap admin and secondary password
were set up.

## 4. Try it without a frontend

Use Postman, Thunder Client, or curl. Example flow:

```bash
# 1. Log in as the bootstrap admin
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@ulpf.local","password":"ChangeMe123!"}'
# -> copy the "token" from the response

# 2. Upload a sample log (use the token above)
curl -X POST http://localhost:3000/api/logs/upload \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"rawLog":"CEF:0|Cisco|ASA|9.1|106023|Deny tcp connection|5|src=192.168.1.20 dst=10.0.0.5 act=denied proto=TCP","sourceType":"cef"}'
# -> copy the "eventId" from the response

# 3. View it masked
curl http://localhost:3000/api/logs/<EVENT_ID> \
  -H "Authorization: Bearer <TOKEN>"

# 4. Unlock the real content (admin already has sensitiveAccess = true)
curl -X POST http://localhost:3000/api/logs/<EVENT_ID>/unlock \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"secondaryPassword":"Unlock123!"}'
```

## API contract (do not change without updating the frontend too)

| Method | Path | Auth | Body | Notes |
|---|---|---|---|---|
| POST | /api/auth/register | none | `{email, password}` | new user starts as role "pending" |
| POST | /api/auth/login | none | `{email, password}` | -> `{token, role}` |
| POST | /api/logs/upload | any logged-in user | `{rawLog, sourceType}` | -> `{eventId, status}` |
| GET | /api/logs/search?query= | any logged-in user | — | masked results |
| GET | /api/logs/:eventId | any logged-in user | — | masked event |
| POST | /api/logs/:eventId/unlock | sensitive-access user | `{secondaryPassword}` | unmasked event |
| GET | /api/alerts | any logged-in user | — | list of alerts |
| POST | /api/access-requests | any logged-in user | — | request sensitive access |
| GET | /api/access-requests | admin | — | list all requests |
| POST | /api/access-requests/:id/approve | admin | — | grants sensitive access |
| POST | /api/access-requests/:id/reject | admin | — | |
| GET | /api/admin/users | admin | — | list all users |
| POST | /api/admin/users/:id/role | admin | `{role}` | pending/viewer/analyst/admin |
| POST | /api/admin/users/:id/revoke-sensitive | admin | — | revoke sensitive access anytime |
| POST | /api/admin/secondary-password | admin | `{newPassword}` | changes the shared unlock code |
| GET | /api/admin/audit | admin | — | recent important actions |

## What each security layer does

1. **Masking (first layer)** — `src/utils/masking.js`. Regex rules mask
   emails, phone numbers, API keys, passwords, and the host portion of
   IPv4 addresses before a normal user ever sees a log.
2. **AES-256-GCM (second layer)** — `src/utils/crypto.js`. The full
   normalized event + raw log is encrypted before it's stored in
   PostgreSQL. Only the `/unlock` route ever decrypts it, and only after
   checking both the user's approval flag and the secondary password.
3. **Role-based access** — `src/middleware/role.js`. Admin / Analyst /
   Viewer, checked on every protected route.
4. **Audit log** — every approval, unlock, and admin change is recorded
   in `audit_log` (`src/services/audit.js`).

## Project structure

```
src/
  server.js          entry point, security middleware, route mounting
  db.js              Postgres pool + schema + bootstrap admin/password
  middleware/         auth.js (JWT check), role.js (role guard)
  utils/               crypto.js (AES-256-GCM), masking.js (regex rules)
  parsers/            one file per format (syslog, json, cef, leef, csv)
                       + detect.js which tries each one in turn
  services/           normalize.js, alerts.js (anomaly detection),
                       audit.js
  routes/             auth.js, logs.js, alerts.js, accessRequests.js,
                       admin.js
sample-logs/          safe demo logs matching the spec's demo flow
```

Adding a new vendor log format = adding one new file in `parsers/` and
one line in `parsers/detect.js`. Nothing else needs to change.
