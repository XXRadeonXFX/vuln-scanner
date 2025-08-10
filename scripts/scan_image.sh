#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-}"
: "${IMAGE:?Usage: scripts/scan_image.sh <image[:tag]>}"

# load env if present
if [ -f "config/policy.env" ]; then
  set -a
  . config/policy.env
  set +a
fi

mkdir -p reports

python3 -m pip install -r requirements.txt --quiet
python3 scripts/scan_image.py \
  --image "$IMAGE" \
  --report-dir "reports" \
  --severity-threshold "${SEVERITY_FAIL_LEVEL:-HIGH}" \
  $( [ "${IGNORE_UNFIXED:-true}" = "true" ] && echo "--ignore-unfixed" )

