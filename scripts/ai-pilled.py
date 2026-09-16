#!/usr/bin/env python3
"""Run ai-pilled from any working directory without installing a package."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai_pilled.__main__ import main

if __name__ == '__main__':
    raise SystemExit(main())
