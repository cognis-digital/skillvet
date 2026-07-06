#!/usr/bin/env bash
# skillvet installer (macOS / Linux). Stdlib-only core — no runtime deps to pull.
#   ./install.sh            install skillvet (core)
#   ./install.sh --content  also install the optional shrike-sec content scan
set -euo pipefail

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "skillvet: need Python 3.10+ (set \$PYTHON to override)" >&2
  exit 1
fi

EXTRA=""
if [ "${1:-}" = "--content" ]; then EXTRA="[content]"; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
echo "Installing skillvet${EXTRA} with $("$PY" --version)"
"$PY" -m pip install --upgrade "${HERE}${EXTRA:+.[content]}" 2>/dev/null || "$PY" -m pip install --upgrade "${HERE}"

echo
echo "Installed. Try:"
echo "  skillvet vet ./some-skill"
echo "  skillvet vet ./some-skill -f sarif > skillvet.sarif"
