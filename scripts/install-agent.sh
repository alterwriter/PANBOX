#!/bin/sh
# Install one release agent binary into a CI workspace; no system-wide changes.
set -eu

version=${1:?usage: sh install-agent.sh vVERSION [install-directory]}
destination=${2:-.panbox/bin}
case "$version" in
  v[0-9]* ) ;;
  * ) echo "Expected a pinned release tag such as v0.1.0-alpha.7" >&2; exit 2 ;;
esac
case "$version" in
  *[!A-Za-z0-9._-]* ) echo "Invalid release tag" >&2; exit 2 ;;
esac

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "Use install-agent.ps1 on Windows" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Unsupported CPU architecture" >&2; exit 2 ;;
esac

asset="panbox-agent_${os}_${arch}"
base="https://github.com/alterwriter/PANBOX/releases/download/${version}"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --retry 3 "$base/$asset" --output "$temporary/$asset"
curl --fail --location --silent --show-error --retry 3 "$base/SHA256SUMS" --output "$temporary/SHA256SUMS"
checksum=$(awk -v name="$asset" '$2 == name { print $0 }' "$temporary/SHA256SUMS")
[ -n "$checksum" ] || { echo "Release checksum for $asset is missing" >&2; exit 2; }
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$temporary" && printf '%s\n' "$checksum" | sha256sum -c -)
else
  (cd "$temporary" && printf '%s\n' "$checksum" | shasum -a 256 -c -)
fi
mkdir -p "$destination"
cp "$temporary/$asset" "$destination/panbox"
chmod 0755 "$destination/panbox"
printf 'Installed PANBOX agent %s at %s/panbox\n' "$version" "$destination"
