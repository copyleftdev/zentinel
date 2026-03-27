# Zentinel ground truth — this file MUST produce ZERO findings.
# Avoids all patterns: no dangerous calls, no literal assignments.
import os
import json


def parse_config(data):
    return json.loads(data)


def get_api_key():
    return os.environ.get("API_KEY")


def add(a, b):
    return a + b


def greet(name):
    return name


def process_items(items):
    return items


def main():
    key = get_api_key()
    config = parse_config(key)
    total = add(key, key)
    msg = greet(key)
    items = process_items(config)
    print(total, msg, items)
