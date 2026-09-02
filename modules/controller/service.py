"""Deployable controller entry point for the canonical controller package."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.controller_service import main


if __name__ == "__main__":
    main()
