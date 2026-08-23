"""
One-off manual maintenance script, not part of the automated pipeline (run from the repository root).

Debug: Analyze why so many threats are classified as 'other'
"""

import sqlite3
from core.classifier import ImprovedThreatClassifier

db_path = 'data/threats.db'
classifier = ImprovedThreatClassifier()

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get sample of "other" threats
cursor.execute('SELECT threat_id, title, description, source FROM threats WHERE threat_type = "other" LIMIT 30')
others = cursor.fetchall()

print("=== SAMPLE OF 'OTHER' THREATS (30) ===\n")

for threat_id, title, description, source in others:
    text = (title + ' ' + (description or '')).lower()
    
    # Score against each category
    scores = {}
    for cat, keywords in classifier.keywords.items():
        matches = sum(1 for kw in keywords if kw.lower() in text)
        scores[cat] = matches
    
    best_cat = max(scores, key=scores.get)
    best_score = scores[best_cat]
    
    print(f"ID: {threat_id} | Source: {source}")
    print(f"Title: {title}")
    print(f"Best match: {best_cat} (score: {best_score})")
    print(f"All scores: {scores}")
    print()

conn.close()