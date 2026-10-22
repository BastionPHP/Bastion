#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# The site renders CLI help using a real Linux build, including on Vercel.
tool_dir="$(mktemp -d)"
go_archive="go1.27.3.linux-amd64.tar.gz"
go_sha256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
curl -fsSL --retry 3 "https://go.dev/dl/${go_archive}" -o "$tool_dir/go.tar.gz"
printf '%s  %s\n' "$go_sha256" "$tool_dir/go.tar.gz" | sha256sum --check
tar -xzf "$tool_dir/go.tar.gz" -C "$tool_dir"
export PATH="$tool_dir/go/bin:$PATH"
CGO_ENABLED=0 go build -trimpath -o "$tool_dir/bastion" ./cmd/bastion
export BASTION_BIN="$tool_dir/bastion"
node --test site/test/*.test.mjs
node site/build.mjs
