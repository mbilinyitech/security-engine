#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/omni"
python3 -m omnishield doctor
python3 -m pytest -q
python3 -m omnishield sovereign pipeline --rights telemetry
