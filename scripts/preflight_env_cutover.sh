#!/bin/bash
# Production cutover preflight for env-driven operations.

set -euo pipefail

required=(
  MONGO_URI
  JWT_SECRET
  PUBLIC_URL
  FRONTEND_BASE_URL
  CORS_ORIGINS
  STRIPE_SECRET_KEY
  STRIPE_WEBHOOK_SECRET
  CLOUDINARY_CLOUD_NAME
  CLOUDINARY_API_KEY
  CLOUDINARY_API_SECRET
  SMTP_HOST
  SMTP_USER
  SMTP_PASS
  FROM_EMAIL
)

missing=()

for key in "${required[@]}"; do
  v="${!key:-}"
  if [ -z "$v" ]; then
    missing+=("$key")
  fi
done

run_jobs="${RUN_JOBS:-}"
if [ "$run_jobs" = "1" ] || [ "$run_jobs" = "true" ] || [ "$run_jobs" = "yes" ] || [ "$run_jobs" = "on" ]; then
  if [ -z "${INTERNAL_JOBS_TOKEN:-}" ]; then
    missing+=("INTERNAL_JOBS_TOKEN")
  fi
fi

if [ "${#missing[@]}" -gt 0 ]; then
  echo "PREFLIGHT_STATUS=FAIL"
  echo "MISSING_KEYS=$(IFS=,; echo "${missing[*]}")"
  exit 1
fi

placeholder_hits=0
for key in "${required[@]}"; do
  v="$(printf '%s' "${!key:-}" | tr '[:upper:]' '[:lower:]')"
  if echo "$v" | rg -q "(changeme|replace_me|your_|example|dummy|test_key|sample)"; then
    echo "PLACEHOLDER_VALUE=$key"
    placeholder_hits=$((placeholder_hits + 1))
  fi
done

if [ "$placeholder_hits" -gt 0 ]; then
  echo "PREFLIGHT_STATUS=FAIL"
  echo "PLACEHOLDER_COUNT=$placeholder_hits"
  exit 1
fi

if ! echo "${PUBLIC_URL}" | rg -q '^https://'; then
  echo "PREFLIGHT_STATUS=FAIL"
  echo "PUBLIC_URL_NOT_HTTPS=1"
  exit 1
fi

if ! echo "${FRONTEND_BASE_URL}" | rg -q '^https://'; then
  echo "PREFLIGHT_STATUS=FAIL"
  echo "FRONTEND_BASE_URL_NOT_HTTPS=1"
  exit 1
fi

frontend_origin="$(node -e "try{const u=new URL(process.env.FRONTEND_BASE_URL||'');process.stdout.write(u.origin);}catch(e){process.exit(1)}")"
if [ -z "$frontend_origin" ]; then
  echo "PREFLIGHT_STATUS=FAIL"
  echo "FRONTEND_BASE_URL_INVALID=1"
  exit 1
fi

cors_match=0
IFS=',' read -r -a cors_arr <<< "${CORS_ORIGINS}"
for o in "${cors_arr[@]}"; do
  c="$(echo "$o" | xargs)"
  if [ "$c" = "$frontend_origin" ]; then
    cors_match=1
    break
  fi
done

if [ "$cors_match" -ne 1 ]; then
  echo "PREFLIGHT_STATUS=FAIL"
  echo "CORS_MISSING_FRONTEND_ORIGIN=$frontend_origin"
  exit 1
fi

echo "PREFLIGHT_STATUS=PASS"
echo "FRONTEND_ORIGIN=$frontend_origin"
echo "CORS_ORIGIN_COUNT=${#cors_arr[@]}"
