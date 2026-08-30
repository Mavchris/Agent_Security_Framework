"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

Bootstrap a named API key (see core/auth.py, SECURITY.md). There is
deliberately no unauthenticated endpoint or UI flow to create a key - that
would let anyone mint their own - so this script, run directly on the
server by an administrator, is the only way to get one.

Usage:
    python scripts/maintenance/create_api_key.py <label>

The generated key is printed once, in full, and never stored or shown
again - only its SHA-256 hash is persisted. Copy it immediately.
"""

import sys

sys.path.insert(0, '.')

from core.auth import generate_key


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/maintenance/create_api_key.py <label>")
        sys.exit(1)

    label = sys.argv[1]
    try:
        raw_key = generate_key(label)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Created API key for label {label!r}.")
    print()
    print(raw_key)
    print()
    print("Copy this key now - it will not be shown again. Only its hash is stored.")


if __name__ == '__main__':
    main()
