#!/bin/sh
# Bastion installer: downloads a release, verifies it, installs the binary.
#
#   curl -fsSL https://larptard.github.io/bastion/install.sh | sh
#
# Verification: the archive's SHA-256 must match SHA256SUMS. If cosign is
# installed, SHA256SUMS' Sigstore signature must come from this repository's
# release workflow. Set BASTION_REQUIRE_SIGNATURE=1 to make cosign mandatory.
#
# Environment: BASTION_VERSION (default: latest), BASTION_INSTALL_DIR,
# BASTION_DOWNLOAD_URL (a mirror holding the same release files; the
# checksum and signature checks still apply).
# Nothing is installed besides the single binary.
set -eu

REPO="larptard/bastion"
VERSION="${BASTION_VERSION:-latest}"
REQUIRE_SIG="${BASTION_REQUIRE_SIGNATURE:-0}"

say() { printf '  %s\n' "$*"; }
die() { printf '  error: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); Bastion runs on Linux and macOS" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { case "$1" in https://*) curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" ;; *) curl -fsSL -o "$2" "$1" ;; esac; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required to verify the download"
fi

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi
base="${BASTION_DOWNLOAD_URL:-$base}"
asset="bastion_${os}_${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: SHA256SUMS"

expected="$(awk -v f="$asset" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
actual="$(sha256 "$tmp/$asset")"
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
say "sha256 ok  $actual"

if command -v cosign >/dev/null 2>&1; then
  fetch "$base/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json" || die "download failed: SHA256SUMS.sigstore.json"
  cosign verify-blob --bundle "$tmp/SHA256SUMS.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$tmp/SHA256SUMS" >/dev/null 2>&1 || die "signature verification failed for SHA256SUMS"
  say "signature ok (sigstore, $REPO release workflow)"
elif [ "$REQUIRE_SIG" = "1" ]; then
  die "cosign not found and BASTION_REQUIRE_SIGNATURE=1"
else
  say "cosign not found: skipped signature check (checksum verified)"
fi

tar -xzf "$tmp/$asset" -C "$tmp" bastion || die "could not extract $asset"

dir="${BASTION_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ "$(id -u)" = "0" ] || [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/bastion" "$dir/bastion" 2>/dev/null || { cp "$tmp/bastion" "$dir/bastion" && chmod 0755 "$dir/bastion"; }
say "installed $("$dir/bastion" version) to $dir/bastion"
case ":$PATH:" in *":$dir:"*) ;; *) say "note: $dir is not in PATH" ;; esac
say "next: sudo bastion scan"
