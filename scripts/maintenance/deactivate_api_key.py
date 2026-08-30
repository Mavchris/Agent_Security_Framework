"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

Revoke a named API key (see core/auth.py, SECURITY.md). Sets is_active=0
rather than deleting the row, so past attribution
(created_by_key_label/deactivated_by_key_label on registered_agents,
monitoring_logs, monitoring_alerts) stays meaningful.

Usage:
    python scripts/maintenance/deactivate_api_key.py <label>
"""

import sys

sys.path.insert(0, '.')

from core.auth import deactivate_key


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/maintenance/deactivate_api_key.py <label>")
        sys.exit(1)

    label = sys.argv[1]
    if deactivate_key(label):
        print(f"Deactivated API key for label {label!r}.")
    else:
        print(f"No API key found for label {label!r}.")
        sys.exit(1)


if __name__ == '__main__':
    main()
