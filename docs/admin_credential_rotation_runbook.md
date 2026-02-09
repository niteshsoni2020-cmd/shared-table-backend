# Admin Credential Rotation Runbook

## Scope
- Rotate admin login email/password directly in MongoDB (DB-backed).
- Invalidate previous sessions by incrementing `tokenVersion`.
- No seed-file hardcoded admin email dependency.

## Required env
- `MONGO_URI`
- `ADMIN_EMAIL` (new admin email)
- `ADMIN_PASSWORD` (new admin password, minimum 12 chars)

## Optional env
- `ADMIN_NAME` (display name)
- `ADMIN_CURRENT_EMAIL` (current admin email, if known)
- `ADMIN_ROTATE_ALLOW_CREATE=true` (bootstrap only when no admin exists)

## Command
```bash
cd Shared-Story-backend
node src/admin/rotate_admin_credentials.js
```

## Expected success output
```json
{"ok":true,"data":{"created":false,"before":{"id":"...","email":"...","role":"Admin","isAdmin":true,"tokenVersion":1},"after":{"id":"...","email":"...","role":"Admin","isAdmin":true,"tokenVersion":2}}}
```

## Safety checks
1. Confirm `after.email` is expected.
2. Confirm `after.role=Admin` and `after.isAdmin=true`.
3. Confirm `tokenVersion` increased (session invalidation applied).
4. Login with new credentials and verify old sessions are rejected.

## Rollback
1. Re-run the same rotation command with previous known-good credentials.
2. Re-verify admin login + role.
