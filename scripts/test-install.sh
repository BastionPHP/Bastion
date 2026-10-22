#!/usr/bin/env bash
# Exercises scripts/install.sh against a local fake release: a good archive
# must install, a tampered one must be rejected. Usage: test-install.sh <bastion-binary>
set -euo pipefail
bin=$(realpath "$1")
root=$(cd "$(dirname "$0")/.." && pwd)
rel=$(mktemp -d)
trap 'kill $srv 2>/dev/null || true; rm -rf "$rel"' EXIT
os=$(uname -s | tr A-Z a-z); arch=$(uname -m); case $arch in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
mkdir "$rel/pkg" && cp "$bin" "$rel/pkg/bastion"
tar -C "$rel/pkg" -czf "$rel/bastion_${os}_${arch}.tar.gz" bastion
(cd "$rel" && sha256sum "bastion_${os}_${arch}.tar.gz" > SHA256SUMS)
(cd "$rel" && exec python3 -m http.server 8765 >/dev/null 2>&1) & srv=$!
sleep 1
export BASTION_DOWNLOAD_URL=http://127.0.0.1:8765
BASTION_INSTALL_DIR="$rel/ok" sh "$root/scripts/install.sh"
"$rel/ok/bastion" version
echo garbage >> "$rel/bastion_${os}_${arch}.tar.gz"
if BASTION_INSTALL_DIR="$rel/bad" sh "$root/scripts/install.sh"; then echo "tampered archive was installed" >&2; exit 1; fi
if BASTION_REQUIRE_SIGNATURE=1 BASTION_INSTALL_DIR="$rel/bad2" sh "$root/scripts/install.sh"; then echo "missing signature accepted" >&2; exit 1; fi
echo "installer checks ok"
