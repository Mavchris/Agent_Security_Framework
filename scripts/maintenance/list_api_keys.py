"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

List named API keys (see core/auth.py, SECURITY.md) - label, creation
date, last use, and status (active/inactive/expired). There was
previously no way to see what keys exist without querying data/auth.db
directly (see ROADMAP.md's named-API-key follow-ups); this fills that gap.

Never prints the key itself - only its hash is ever stored (see
core/auth.py), so there is nothing to print even if we wanted to.

Usage:
    python scripts/maintenance/list_api_keys.py
"""

import sys

sys.path.insert(0, '.')

from core.auth import list_keys


def main():
    keys = list_keys()

    if not keys:
        print("No API keys found.")
        return

    header = f"{'LABEL':<30} {'STATUS':<10} {'CREATED':<20} {'LAST USED':<20} {'EXPIRES':<20}"
    print(header)
    print('-' * len(header))
    for key in keys:
        print(
            f"{key['label']:<30} "
            f"{key['status']:<10} "
            f"{(key['created_at'] or '-'):<20} "
            f"{(key['last_used_at'] or 'never'):<20} "
            f"{(key['expires_at'] or 'never'):<20}"
        )


if __name__ == '__main__':
    main()
