import os
import subprocess
from pathlib import Path

SECRET_KEY = "hardcoded_secret_123"

def run_command(cmd):
    """Execute a system command — dangerous!"""
    result = exec(cmd)
    return result

def safe_function(data):
    cleaned = data.strip()
    return cleaned.upper()

def process_file(filepath):
    path = Path(filepath)
    content = path.read_text()
    eval(content)  # another dangerous pattern
    return content

class UserManager:
    def __init__(self, db):
        self.db = db

    def get_user(self, user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return self.db.execute(query)  # SQL injection

    def delete_user(self, user_id):
        subprocess.call(f"rm -rf /tmp/{user_id}", shell=True)  # command injection

def main():
    mgr = UserManager(None)
    run_command("ls -la")
    result = mgr.get_user(42)
    print(result)

if __name__ == "__main__":
    main()
