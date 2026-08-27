"""
One-off maintenance script, not part of the automated pipeline (run from the
repository root).

Backfills translation for threats that were scraped before core/translation.py
existed (Vague 3a):

1. Sets source_language on pre-existing CNVD/FSTEC/CERT-FR rows (the scraper
   only started stamping this field going forward).
2. Translates every row that has a source_language but no translation yet
   (translated_at IS NULL), per the field policy in
   core/translation.py:FIELDS_TO_TRANSLATE.

Safe to re-run: only touches rows missing source_language or translated_at,
so already-translated rows are left alone. Requires argostranslate + the
zh/ru/fr->en models to be installed (see
scripts/maintenance/install_translation_models.py) - without them, this
still runs but every row logs a clear skip and stays untranslated (see
core/translation.py).
"""

import sqlite3
import sys

sys.path.insert(0, '.')

from core.translation import translate_threat_fields

DB_PATH = 'data/threats.db'

# Source -> language, for rows scraped before the CIRCL scraper stamped
# source_language itself.
SOURCE_LANGUAGE = {
    'CNVD': 'zh',
    'FSTEC': 'ru',
    'CERT-FR': 'fr',
}


def migrate_schema(conn):
    for column, coltype in [
        ('source_language', 'TEXT'),
        ('title_translated', 'TEXT'),
        ('description_translated', 'TEXT'),
        ('translated_at', 'TIMESTAMP'),
    ]:
        try:
            conn.execute(f'ALTER TABLE threats ADD COLUMN {column} {coltype}')
            conn.commit()
            print(f"Added {column} column.")
        except sqlite3.OperationalError:
            pass  # column already exists


def backfill_source_language(conn):
    updated = 0
    for source, lang in SOURCE_LANGUAGE.items():
        cursor = conn.execute(
            'UPDATE threats SET source_language = ? WHERE source = ? AND source_language IS NULL',
            (lang, source),
        )
        updated += cursor.rowcount
    conn.commit()
    print(f"Backfilled source_language on {updated} row(s).")


def backfill_translations(conn):
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        'SELECT id, title, description, source_language FROM threats '
        'WHERE source_language IS NOT NULL AND translated_at IS NULL'
    ).fetchall()

    print(f"{len(rows)} row(s) eligible for translation.")

    translated = 0
    skipped = 0

    for row in rows:
        result = translate_threat_fields(row['title'], row['description'], row['source_language'])

        if result['translated_at'] is None:
            skipped += 1
            continue

        conn.execute(
            'UPDATE threats SET title_translated = ?, description_translated = ?, translated_at = ? WHERE id = ?',
            (result['title_translated'], result['description_translated'], result['translated_at'], row['id']),
        )
        translated += 1

    conn.commit()
    print(f"Translated {translated} row(s), skipped {skipped} (translation unavailable/failed - see [WARN] logs above).")


def main():
    conn = sqlite3.connect(DB_PATH)
    migrate_schema(conn)
    backfill_source_language(conn)
    backfill_translations(conn)
    conn.close()


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    main()
