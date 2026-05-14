#!/usr/bin/env bash
set -euo pipefail

TS=$(date +"%Y-%m-%d_%H-%M-%S")
OUT="run_$TS"
mkdir -p "$OUT"

sudo cp -v /var/log/suricata/fast.log "$OUT/" 2>/dev/null || true
sudo cp -v /var/log/suricata/eve.json "$OUT/" 2>/dev/null || true
sudo cp -v /var/log/suricata/stats.log "$OUT/" 2>/dev/null || true

echo "Saved logs to: $PWD/$OUT"
ls -lh "$OUT"
