import sqlite3, os

db_path = os.path.abspath("market.db")
print("🧨 연결된 DB 경로:", db_path)

conn = sqlite3.connect("market.db")
cursor = conn.cursor()

cursor.execute("DELETE FROM user WHERE username = 'admin'")
conn.commit()
conn.close()

print("✅ 'admin' 계정 삭제 완료")