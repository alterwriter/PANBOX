#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 1; }
base_url=${PANBOX_SERVER:-http://127.0.0.1:8080}
email=${PANBOX_BOOTSTRAP_EMAIL:-admin@panbox.local}
if [[ -z ${PANBOX_BOOTSTRAP_PASSWORD:-} ]]; then
  read -rsp 'PANBOX admin password: ' PANBOX_BOOTSTRAP_PASSWORD
  printf '\n'
fi
cookie_file=$(mktemp)
trap 'rm -f "$cookie_file"' EXIT
login=$(jq -nc --arg email "$email" --arg password "$PANBOX_BOOTSTRAP_PASSWORD" '{email:$email,password:$password}')
csrf=$(curl -fsS -c "$cookie_file" -H 'Content-Type: application/json' -d "$login" "$base_url/v1/auth/login" | jq -r '.csrf_token')
[[ -n "$csrf" && "$csrf" != null ]] || { echo 'Login failed' >&2; exit 1; }
for entry in 'alpha-api:900001:repo-alpha-main.json:repo-alpha-feature.json' 'beta-web:900002:repo-beta-main.json:repo-beta-feature-partial.json'; do
  IFS=: read -r name project first second <<< "$entry"
  body=$(jq -nc --arg name "$name" --arg project "$project" '{name:$name,provider:"gitlab",provider_project_id:$project,default_branch:"main",owner:"Demo"}')
  repo=$(curl -sS -b "$cookie_file" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d "$body" "$base_url/v1/repos")
  id=$(jq -r '.id // empty' <<< "$repo")
  if [[ -z "$id" ]]; then
    id=$(curl -fsS -b "$cookie_file" "$base_url/v1/repos" | jq -r --arg project "$project" '.[] | select(.provider_project_id==$project) | .id' | head -n 1)
  fi
  [[ -n "$id" ]] || { echo "Could not enroll $name" >&2; exit 1; }
  token=$(curl -fsS -b "$cookie_file" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d '{"label":"demo-seed","expires_hours":24}' "$base_url/v1/repos/$id/scan-tokens" | jq -r '.secret')
  for fixture in "$first" "$second"; do
    jq --arg id "$id" 'walk(if type=="string" and startswith("REPLACE_") and endswith("_ID") then $id else . end)' "test/fixtures/$fixture" |
      curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' --data-binary @- "$base_url/v1/scans" >/dev/null
  done
  printf 'Seeded %s: %s\n' "$name" "$id"
done
