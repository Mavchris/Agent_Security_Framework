"""
Fix: Use title + detection_keywords instead of description
"""

import sqlite3

db_path = 'data/threats.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Check what data we have
cursor.execute('SELECT threat_id, title, description, detection_keywords FROM threats LIMIT 5')
sample = cursor.fetchall()

print("=== DATA STRUCTURE CHECK ===\n")
for threat_id, title, desc, keywords in sample:
    print(f"ID: {threat_id}")
    print(f"Title: {title}")
    print(f"Description: {desc[:50] if desc else 'EMPTY'}...")
    print(f"Keywords: {keywords}")
    print()

conn.close()