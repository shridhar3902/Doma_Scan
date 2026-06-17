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

# Ensure local directories take precedence in path (resolving symlinks)
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

try:
    from modules.cli import main
except ModuleNotFoundError as e:
    if "modules" in str(e):
        print(f"\n[CRITICAL ERROR] Python cannot find the 'modules' directory.")
        print(f"Expected to find it here: {os.path.join(os.path.dirname(os.path.realpath(__file__)), 'modules')}")
        print("\nSolution: Please make sure you cloned the entire repository, and that the 'modules' folder exists next to this script.")
        sys.exit(1)
    raise


if __name__ == "__main__":
    raise SystemExit(main())
