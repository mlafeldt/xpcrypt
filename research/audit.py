#!/usr/bin/env python3
"""Superseded - use audit2.py.

This was the first block row-count audit.  It reads the database with the
strict reader in dbscan.py, which rejects three of the five V2 databases
because their cheat names start with control bytes (FINDINGS.md 4.1), so it
dies with a TypeError on xteng.dec, xtger.dec and the USA ROM.

audit2.py is the same audit on top of the tolerant reader in db2.py, and is the
one the notes quote.  Kept only so that a reference to "audit.py" leads here.
"""
import sys

sys.exit(__doc__)
