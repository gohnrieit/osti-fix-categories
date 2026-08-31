#!/usr/bin/env bash
# Copy Win7 / Categories overlay files onto a gearmulator 1.4.2 tree.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-}"
if [[ -z "$DEST" ]]; then
  echo "usage: $0 /path/to/gearmulator-1.4.2" >&2
  exit 1
fi
cp -a "$ROOT/overlay/." "$DEST/"
python3 "$ROOT/scripts/check_categories_fixes.py" "$DEST"
echo "Overlay applied to $DEST"
