"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

Bootstrap a named API key (see core/auth.py, SECURITY.md). There is
deliberately no unauthenticated endpoint or UI flow to create a key - that
would let anyone mint their own - so this script, run directly on the
server by an administrator, is the only way to get one.

Usage:
    python scripts/maintenance/create_api_key.py <label>
    python scripts/maintenance/create_api_key.py <label> --expires-in-days 90

Without --expires-in-days, the key never expires - the same behavior as
before this flag existed, so existing usage of this script (and every
already-issued key) is unaffected; expiration is opt-in per key.

The generated key is printed once, in full, and never stored or shown
again - only its SHA-256 hash is persisted. Copy it immediately.
"""

import argparse
import sys

sys.path.insert(0, '.')

from core.auth import generate_key


def main():
    parser = argparse.ArgumentParser(
        description="Create a named API key (see core/auth.py, SECURITY.md)."
    )
    parser.add_argument('label', help="Unique label to identify this key")
    parser.add_argument(
        '--expires-in-days', type=int, default=None, metavar='N',
        help="Key stops working N days from now. Omit for no expiration (default).",
    )
    args = parser.parse_args()

    try:
        raw_key = generate_key(args.label, expires_in_days=args.expires_in_days)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Created API key for label {args.label!r}.")
    if args.expires_in_days is not None:
        print(f"Expires in {args.expires_in_days} day(s).")
    print()
    print(raw_key)
    print()
    print("Copy this key now - it will not be shown again. Only its hash is stored.")


if __name__ == '__main__':
    main()
