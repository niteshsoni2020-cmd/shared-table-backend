# Production Cutover Checklist

## 1. Environment preparation
1. Copy `env.example` to `.env` and fill real values.
2. Confirm `FRONTEND_BASE_URL` uses final frontend domain.
3. Confirm `CORS_ORIGINS` includes `FRONTEND_BASE_URL` origin.
4. Confirm Stripe live keys + webhook secret are set.
5. Confirm SMTP credentials and `FROM_EMAIL` are set.
6. Confirm `INTERNAL_JOBS_TOKEN` is set when `RUN_JOBS=true`.

## 2. Preflight validation
```bash
cd Shared-Story-backend
./scripts/preflight_env_cutover.sh
```

Expected:
- `PREFLIGHT_STATUS=PASS`

## 3. Smoke validation (local/staging)
Run with the same env set that will be used in deployment:
```bash
cd Shared-Story-backend
npm test --silent
curl -sS https://<api-domain>/ready
curl -sS https://<api-domain>/health
curl -sS -o /dev/null -w '%{http_code}\n' https://<api-domain>/api/auth/me
```

Expected:
- backend test command is green
- `/ready` and `/health` return `{"ok":true,...}`
- unauthenticated `/api/auth/me` returns `401`/`403`

## 4. Admin credential rotation
```bash
cd Shared-Story-backend
ADMIN_EMAIL=<new_admin_email> \
ADMIN_PASSWORD=<new_admin_password> \
ADMIN_CURRENT_EMAIL=<old_admin_email_optional> \
node src/admin/rotate_admin_credentials.js
```

Expected:
- `ok=true`
- `after.tokenVersion` incremented

## 5. Post-cutover checks
1. Admin login works with rotated credentials.
2. Host/user login and booking flows work.
3. Stripe checkout + webhook events are processed.
4. Email verification + reset-password emails are delivered.
