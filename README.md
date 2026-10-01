# Starter Kit — Backend (Node + Express, JavaScript/ESM)

The **canonical** REST API and the reference implementation of the DPDP
compliance layer. Node · Express 5 · Mongoose (MongoDB) · Redis (cache).

> This is the JS source of truth. `backnd-ts/` is the TypeScript mirror and
> `next-starter-kit/src/server` is the Next.js port — keep all three in sync.

## Commands

```bash
npm install
cp .env.example .env      # if present; otherwise create it (see below)
npm run dev               # node scripts/dev-mongo.js (spins a dev Mongo, then starts)
npm run dev:real          # nodemon -r dotenv/config src/server.js
npm start                 # node -r dotenv/config src/server.js
npm run lint              # eslint "src/**/*.js"
npm run format            # prettier
npm run retention         # DPDP retention/erasure pass (Rule 8)
npm run retention:dry     # report-only retention pass
```

There is **no test framework** in this repo.

## Environment (`.env`)

**Core**

| Var | Purpose |
| --- | --- |
| `NODE_SERVER_PORT` | HTTP port (frontend `.env` points at this). |
| `ALLOWED_ORIGINS` | Comma-separated CORS allowlist (must include the frontend origin). |
| `MONGODB_URL` | Mongo connection string. |
| `REDIS_URL` | Optional Redis cache. |
| `TRUST_PROXY_COUNT` | Express `trust proxy` hop count (set to real hops in prod). |

**Auth / sessions**

`ACCESS_TOKEN_SECRET` (also the CSRF signing key) · `PASSWORD_PEPPER` (mixed into
password hashing via HMAC-SHA256; never stored) · `IDLE_NORMAL` / `IDLE_REMEMBER`
/ `ROTATION_WINDOW` (ms session timings) · SMTP `SMTP_*` for email ·
`RECAPTCHA_SECRET_KEY` / `RECAPTCHA_TIMEOUT_MS` · `PASSKEY_ORIGIN` /
`PASSKEY_RP_ID` / `PASSKEY_RP_NAME`.

**DPDP**

`DPDP_FIELD_KEY` (AES-256-GCM field encryption) · `DPDP_FIELD_KEY_ID` ·
`DPDP_TOKEN_SECRET` (pseudonymous HMAC tokens) · `DPO_NAME` / `DPO_EMAIL` /
`DPO_PHONE` / `DPO_ADDRESS` (Rule 9 contact) · `DPB_COMPLAINT_URL` ·
`DPDP_INACTIVITY_DAYS` · `DPDP_RETENTION_INTERVAL_MS`.

## Boot

`src/server.js` connects MongoDB before `app.listen`. `src/app.js` wires Express:
CORS allowlist + localhost, Helmet CSP (allows Google reCAPTCHA), global rate
limit, JSON body (`10kb`), mongo-sanitize, cookie-parser, CSRF, static, routers,
then the global error handler.

## Architecture

- **Session/cookie auth** (not JWT). Login creates a `Session` doc and sets
  httpOnly `session_id`, `device_id`, `_csrf_token` cookies. TOTP 2FA puts the
  session in `PENDING_2FA` until `POST /user/2fa/verify`.
- `middlewares/auth.middleware.js` validates the session cookie, binds it to
  `device_id` + UA hash, enforces idle timeout, rotates periodically, and attaches
  `req.user`. Use `authMiddleware()` or `authMiddleware(["admin"])`.
- **CSRF** is a double-submit (signed, expiring token); skipped for GET/HEAD/OPTIONS.
- **Controllers** are wrapped by `requestHandler`, throw `ApiError`, return
  `ApiResponse`; bodies validated against zod schemas via `validate`.
- **DTOs** (`dto/user.dto.js`) whitelist output fields — never return raw docs.
- **Models**: `User`, `Session`, `AuditLog`, plus DPDP models (`Consent`,
  `RightsRequest`, `NomineeClaim`, `Breach`, `TransferRegister`, `Dpia`, …).

## API surface

Base: `/api/v1`. `GET /health` is unauthenticated.

### `/user`
`GET /check-username` · `GET /check-email` · `POST /create` · `POST /login` ·
`GET /verify-email` · `POST /forgot-password` · `POST /reset-password` ·
`POST /logout` · `GET /profile` ·
`POST /2fa/verify` · `GET /2fa/status` · `POST /2fa/generate` · `POST /2fa/change` ·
`POST /change-name` · `POST /change-pass` ·
`GET /sessions` · `POST /sessions/revoke` · `POST /sessions/revoke-all` ·
`GET /passkey/list` · `POST /passkey/register/options` ·
`POST /passkey/register/verify` · `POST /passkey/login/options` ·
`POST /passkey/login/verify` · `DELETE /passkey/:id`

### `/privacy` — Data Principal rights (ss. 5–14)
`GET /notice` · `GET /notice/legacy` · `GET /purposes` ·
`GET /consent` · `POST /consent/grant` · `POST /consent/withdraw` ·
`GET /data` (s.11) · `POST /correct` (s.12) · `POST /erase` (s.12) ·
`POST /grievance` (s.13) · `POST /grievance/escalate` (s.13) ·
`POST /nominate` · `GET /nominees` · `PUT /nominees` ·
`PATCH /nominees/:index` · `DELETE /nominees/:index` (s.14) ·
`GET /cases` · `POST /nominee-claim` (public) ·
`GET /age-status` · `POST /guardian-consent` (s.9 / Rule 10) ·
`GET /audit/verify` (Rule 6(c) self-check)

### `/privacy/cookies` — Domain 8
`GET /` · `POST /consent` · `POST /withdraw`

### `/admin` — strict `authMiddleware(["admin"])`
`GET /users/:id`

### `/admin/privacy` — admin DPDP control plane
`GET /rights` (SLA dashboard) · `GET /rights/cases` · `PATCH /rights/cases/:case_id` ·
`GET /nominee-claims` · `POST /nominee-claims/:claimId/decide` · `GET /nominees/:userId` ·
`GET|POST /breaches` · `GET /breaches/:incidentId/report` ·
`GET /breaches/:incidentId/drafts` · `POST /breaches/:incidentId/notify` ·
`POST /retention/run` · `GET|POST /transfers` · `GET|POST /dpia` ·
`GET /audit/verify` · `GET /audit`

## Security

All `.env` files ship as **empty placeholders**. Before deploying, regenerate and
rotate `MONGODB_URL`, `REDIS_URL`, `SMTP_PASS`, `RECAPTCHA_SECRET_KEY`,
`ACCESS_TOKEN_SECRET` and `PASSWORD_PEPPER` (rotation invalidates stored hashes —
plan a migration). Set `TRUST_PROXY_COUNT` to the real hop count. See
`../DPDP-COMPLIANCE.md` and `../docs/dpdp/` for the compliance maps and artefacts.
