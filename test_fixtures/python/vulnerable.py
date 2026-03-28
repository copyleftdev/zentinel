# Zentinel ground truth — every line with a # TRIGGER comment should fire the named rule.
# Lines without TRIGGER should NOT fire any rule.
import os
import subprocess
import pickle
import yaml
import marshal
import shelve
import hashlib
import ssl
import requests
import tempfile

# ── Command Injection ────────────────────────────────────
def run_user_input(cmd):
    exec(cmd)                                       # TRIGGER python.security.exec-usage

def evaluate_expression(expr):
    return eval(expr)                               # TRIGGER python.security.eval-usage

def system_call(cmd):
    os.system(cmd)                                  # TRIGGER python.security.os-system

def popen_call(cmd):
    os.popen(cmd)                                   # TRIGGER python.security.os-popen

def subprocess_call(cmd):
    subprocess.call(cmd, shell=True)                # TRIGGER python.security.subprocess-shell

def subprocess_run_cmd(cmd):
    subprocess.run(cmd, shell=True)                 # TRIGGER python.security.subprocess-run

def subprocess_popen_cmd(cmd):
    subprocess.Popen(cmd, shell=True)               # TRIGGER python.security.subprocess-popen

# ── Deserialization ──────────────────────────────────────
def load_pickle(f):
    return pickle.load(f)                           # TRIGGER python.security.pickle-load

def loads_pickle(data):
    return pickle.loads(data)                       # TRIGGER python.security.pickle-loads

def load_yaml(f):
    return yaml.load(f)                             # TRIGGER python.security.yaml-load

def load_marshal(data):
    return marshal.loads(data)                      # TRIGGER python.security.marshal-loads

def open_shelve(path):
    return shelve.open(path)                        # TRIGGER python.security.shelve-open

# ── Cryptography ─────────────────────────────────────────
def hash_md5(data):
    return hashlib.md5(data)                        # TRIGGER python.security.hashlib-md5

def hash_sha1(data):
    return hashlib.sha1(data)                       # TRIGGER python.security.hashlib-sha1

# ── Dangerous Builtins ───────────────────────────────────
def compile_code(source):
    return compile(source, "<string>", "exec")      # TRIGGER python.security.compile-usage

def get_input():
    return input("Enter value: ")                   # TRIGGER python.security.input-python2

# ── Network / TLS ────────────────────────────────────────
def no_verify_ssl():
    return ssl._create_unverified_context()         # TRIGGER python.security.ssl-no-verify

def fetch_url(url):
    return requests.get(url, verify=False)          # TRIGGER python.security.requests-no-verify

# ── Temp Files ───────────────────────────────────────────
def make_temp():
    return tempfile.mktemp()                        # TRIGGER python.security.tempfile-mktemp

# ── Tier 1: Precise Weak Cryptography ────────────────────
def hash_new_md5(data):
    return hashlib.new("md5", data)                 # TRIGGER python.security.hashlib-new-md5

def hash_new_sha1(data):
    return hashlib.new("sha1", data)                # TRIGGER python.security.hashlib-new-sha1

# ── Tier 1: Code Injection via F-String ──────────────────
def eval_fstring(user):
    eval(f"print({user})")                          # TRIGGER python.security.eval-fstring (+ eval-usage)

def exec_fstring(code):
    exec(f"result = {code}")                        # TRIGGER python.security.exec-fstring (+ exec-usage)

# ── Hardcoded Secrets ────────────────────────────────────
API_KEY = "sk-1234567890abcdef"                     # TRIGGER python.security.hardcoded-secret
DATABASE_PASSWORD = "hunter2"                       # TRIGGER python.security.hardcoded-secret
