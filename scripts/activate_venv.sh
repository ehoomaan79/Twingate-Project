#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/../.venv"

if [ -f "$VENV_DIR/bin/activate" ]; then
  . "$VENV_DIR/bin/activate"
else
  echo "Virtual environment not found at $VENV_DIR" >&2
  return 1 2>/dev/null || exit 1
fi
