#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target="$project_dir/.env"
if [ -e "$target" ]; then
  printf '%s\n' '.env already exists; leaving the existing credentials untouched.' >&2
  exit 1
fi

admin_email=${PANBOX_ADMIN_EMAIL:-admin@panbox.local}
host_port=${PANBOX_HOST_PORT:-8080}
db_port=${PANBOX_DB_HOST_PORT:-5434}
case "$admin_email" in *[!A-Za-z0-9._+@-]*|'') echo 'Invalid admin email.' >&2; exit 1;; esac
for port in "$host_port" "$db_port"; do
  case "$port" in *[!0-9]*|'') echo 'Ports must be numeric.' >&2; exit 1;; esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then echo 'Port out of range.' >&2; exit 1; fi
done

secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
db_password=$(secret)
admin_password=$(secret)
scm_key=$(secret)
umask 077
set -C
printf 'PANBOX_DB_PASSWORD=%s\nPANBOX_BOOTSTRAP_EMAIL=%s\nPANBOX_BOOTSTRAP_PASSWORD=%s\nPANBOX_SCM_ENCRYPTION_KEY=%s\nPANBOX_SECURE_COOKIE=false\nPANBOX_HOST_PORT=%s\nPANBOX_DB_HOST_PORT=%s\n' \
  "$db_password" "$admin_email" "$admin_password" "$scm_key" "$host_port" "$db_port" > "$target"
printf 'Created %s with private random credentials.\n' "$target"
