# DEMO FIXTURE: corrected version.
import json, os, subprocess, hashlib
password = os.environ.get("APP_PASSWORD")
def get_user(cur, uid):
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
def run(args):
    subprocess.run(["ls", args], check=True)
def load(blob):
    return json.loads(blob)
def h(p):
    return hashlib.sha256(p.encode()).hexdigest()
