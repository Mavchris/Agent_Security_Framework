import sqlite3

conn = sqlite3.connect('data/threats.db')
cursor = conn.cursor()

print("=== DATABASE VERIFICATION ===\n")

# Count by type
cursor.execute('SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type')
results = cursor.fetchall()

print("Threats by Type:")
for threat_type, count in results:
    print(f"  {threat_type:<25} : {count}")

# Total
cursor.execute('SELECT COUNT(*) FROM threats')
total = cursor.fetchone()[0]
print(f"\nTotal threats in DB: {total}")

# Sample threats
print("\nFirst 5 threats:")
cursor.execute('SELECT threat_id, title, threat_type FROM threats LIMIT 5')
for threat_id, title, threat_type in cursor.fetchall():
    print(f"  - {threat_id:<15} | {title[:40]:<40} | {threat_type}")

conn.close()