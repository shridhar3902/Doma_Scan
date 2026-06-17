#!/usr/bin/env python3
"""
DomaScan v2.0.0 — CLI-based OSINT Domain Intelligence Tool
Developed by Shridhar Kirtane
https://github.com/shridhar3902/DomaScan
"""

__version__ = "2.0.0"
__author__ = "Shridhar Kirtane"

import os
import sys

# Ensure local directories take precedence in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
