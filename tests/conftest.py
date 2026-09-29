"""
NexIDS conftest.py
==================
Pytest configuration shared across all test modules.
Adds the project root to sys.path so imports resolve correctly
regardless of how pytest is invoked.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
