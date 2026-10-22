#!/usr/bin/env bash
# Records real Bastion output for the website and README:
#   site/demo/scan.ansi    `bastion scan` on this machine (+ any running containers)
#   site/demo/trace.ansi   `bastion trace` on the inert lab tree from lab.sh
#   site/demo/report.html  the HTML report built from both
# Run as root on a host with Docker for the most representative output; the
# CI workflow `demo.yml` runs it with a few official PHP images started.
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=${BIN:-./bastion}
OUT=site/demo
LAB=${LAB:-/tmp/bastion-lab}
mkdir -p "$OUT"
export COLUMNS=${COLUMNS:-104}

scripts/demo/lab.sh "$LAB" >/dev/null

"$BIN" scan --color always -q > "$OUT/scan.ansi" || true
"$BIN" scan --json -q > "$OUT/scan.json" || true
"$BIN" trace --sysroot "$LAB" --since 87600h --color always -q > "$OUT/trace.ansi" || true
"$BIN" trace --sysroot "$LAB" --since 87600h --json -q > "$OUT/trace.json" || true
printf 'PHP 8.3.6 (cli) (built: Oct  7 2026 18:06:38) (NTS)\nphp8.3-cli\t8.3.6-0ubuntu0.24.04.12\n' | "$BIN" check --color always > "$OUT/check.ansi" || true
"$BIN" report --scan "$OUT/scan.json" --trace "$OUT/trace.json" -o "$OUT/report.html" -q >/dev/null || [ $? -le 2 ]
rm -f "$OUT/scan.json" "$OUT/trace.json"
{
  echo "recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "bastion: $("$BIN" version)"
  echo "host: $(. /etc/os-release && echo "$PRETTY_NAME") / $(uname -r)"
  echo "containers: $(docker ps --format '{{.Image}}' 2>/dev/null | sort | tr '\n' ' ')"
} > "$OUT/RECORDING.txt"
echo "wrote $OUT/{scan,trace,check}.ansi, report.html"
