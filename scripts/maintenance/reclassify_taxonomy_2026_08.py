"""
One-off manual maintenance script, not part of the automated pipeline (run from the repository root).

Reclassify the entire threats table with the revised 9-category taxonomy
(OWASP LLM Top 10 2025 v2.0 aligned) and populate the new ai_relevant
column for every row. Run once after deploying the Vague 3a taxonomy
change in core/classifier.py; not needed again unless the taxonomy
changes further (in which case a similar one-off script should be added,
not this one re-run blindly).
"""

import sqlite3
import sys

sys.path.insert(0, '.')

from core.classifier import ImprovedThreatClassifier

DB_PATH = 'data/threats.db'


def migrate_schema(conn):
    try:
        conn.execute('ALTER TABLE threats ADD COLUMN ai_relevant BOOLEAN DEFAULT 0')
        conn.commit()
        print("Added ai_relevant column.")
    except sqlite3.OperationalError:
        print("ai_relevant column already exists.")


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    migrate_schema(conn)

    classifier = ImprovedThreatClassifier()
    rows = conn.execute('SELECT * FROM threats').fetchall()
    print(f"Reclassifying {len(rows)} threats...")

    before_counts = {}
    after_counts = {}
    updated = 0

    for row in rows:
        threat = {
            'title': row['title'],
            'description': row['description'],
            'test_payload': row['test_payload'],
            'detection_keywords': row['detection_keywords'],
        }

        before_counts[row['threat_type']] = before_counts.get(row['threat_type'], 0) + 1

        new_type = classifier.classify(threat)
        new_relevant = classifier.is_ai_relevant(threat, new_type)
        after_counts[new_type] = after_counts.get(new_type, 0) + 1

        conn.execute(
            'UPDATE threats SET threat_type = ?, ai_relevant = ? WHERE id = ?',
            (new_type, new_relevant, row['id'])
        )
        updated += 1

    conn.commit()
    conn.close()

    print(f"\nUpdated {updated} rows.\n")

    print("=== BEFORE (old taxonomy) ===")
    total = sum(before_counts.values())
    for cat, n in sorted(before_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:<25}: {n:4d} ({100*n/total:.1f}%)")

    print("\n=== AFTER (new taxonomy) ===")
    for cat, n in sorted(after_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:<25}: {n:4d} ({100*n/total:.1f}%)")


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    main()
