# DEMO FIXTURE: intentionally vulnerable. Never run this.
import pickle, subprocess, hashlib
password = "SuperSecret123"
def get_user(cur, uid):
    cur.execute("SELECT * FROM users WHERE id=" + uid)
def run(cmd):
    subprocess.call(cmd, shell=True)
def load(blob):
    return pickle.loads(blob)
def h(p):
    return hashlib.md5(p.encode()).hexdigest()
