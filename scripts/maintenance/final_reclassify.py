"""
One-off manual maintenance script, not part of the automated pipeline (run from the repository root, writes directly to the threats table).

Smart reclassification - Trusted sources only
"""

import sqlite3
from core.classifier import ImprovedThreatClassifier

db_path = 'data/threats.db'
classifier = ImprovedThreatClassifier()

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print("Smart reclassification...\n")

strategies = {
    'CVE': 'classify',          # CVE = TRUSTED
    'GitHub': 'classify',       # GitHub = CLASSIFY ALL
    'ArXiv': 'classify',        # ArXiv = TRUSTED
    'MITRE ATT&CK': 'classify', # MITRE = CLASSIFY (not generic)
    'Censys': 'api_abuse',      # Censys = ALL api_abuse
    'MISP': 'classify',         # MISP = TRUSTED
    'OpenCTI': 'classify'       # OpenCTI = TRUSTED
}

cursor.execute('SELECT id, title, description, source, detection_keywords FROM threats')
threats = cursor.fetchall()

print(f"Total threats: {len(threats)}\n")

for idx, (threat_id, title, description, source, keywords_str) in enumerate(threats, 1):
    strategy = strategies.get(source, 'classify')
    
    if strategy == 'api_abuse':
        new_type = 'api_abuse'
    else:  # classify
        import json
        try:
            keywords = json.loads(keywords_str) if isinstance(keywords_str, str) else (keywords_str or [])
        except:
            keywords = []
        
        threat_input = {
            'title': title or '',
            'description': description or '',
            'test_payload': '',
            'detection_keywords': keywords
        }
        new_type = classifier.classify(threat_input)
    
    cursor.execute(
        'UPDATE threats SET threat_type = ? WHERE id = ?',
        (new_type, threat_id)
    )
    
    if idx % 50 == 0:
        print(f"{idx}/{len(threats)}")

conn.commit()

# Stats
cursor.execute('SELECT threat_type, COUNT(*) as count FROM threats GROUP BY threat_type ORDER BY count DESC')
stats = cursor.fetchall()

print(f"\nDone!\n")
print("="*60)
print("FINAL DISTRIBUTION")
print("="*60 + "\n")

total = sum(count for _, count in stats)
for threat_type, count in stats:
    pct = (count / total * 100)
    bar = "#" * int(pct / 2)
    print(f"{threat_type:<25} : {count:3d} ({pct:5.1f}%) {bar}")

conn.close()