import os, mysql.connector, binascii
from app.common.utils import sha256_hex, rand_bytes
from dotenv import load_dotenv
load_dotenv()

CONF = dict(
    host=os.getenv("MYSQL_HOST","127.0.0.1"),
    port=int(os.getenv("MYSQL_PORT","3306")),
    user=os.getenv("MYSQL_USER","securechat"),
    password=os.getenv("MYSQL_PASS",""),
    database=os.getenv("MYSQL_DB","securechat"),
    autocommit=True
)

def connect():
    return mysql.connector.connect(**CONF)

def init_schema():
    c = connect()
    cur = c.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE,
      username VARCHAR(255) UNIQUE,
      salt VARBINARY(16),
      pwd_hash CHAR(64)
    ) ENGINE=InnoDB;
    """)
    cur.close()
    c.close()

def create_user(email: str, username: str, password_plain: str):
    salt = rand_bytes(16)
    pwd_hash = sha256_hex(salt + password_plain.encode())
    c = connect(); cur = c.cursor()
    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                (email, username, salt, pwd_hash))
    cur.close(); c.close()
    return True

def find_user_by_email(email: str):
    c = connect(); cur = c.cursor()
    cur.execute("SELECT id,email,username,salt,pwd_hash FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close(); c.close()
    if not row: return None
    return {"id":row[0],"email":row[1],"username":row[2],"salt":row[3],"pwd_hash":row[4]}

def verify_password(email: str, password_plain: str) -> bool:
    u = find_user_by_email(email)
    if not u: return False
    recomputed = sha256_hex(u['salt'] + password_plain.encode())
    # constant-time compare
    return binascii.hexlify(u['pwd_hash'].encode() if isinstance(u['pwd_hash'],str) else u['pwd_hash']) == binascii.hexlify(recomputed.encode())
