---
layout: default
title: Rules
nav_order: 4
---

# Rules

## Built-in rule sets

Zentinel ships with 36 security rules across three files.

### Python (`rules/python-security.yaml`)

20 rules covering:

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `python.security.exec-usage` | `exec(...)` | ERROR |
| `python.security.eval-usage` | `eval(...)` | ERROR |
| `python.security.os-system` | `os.system(...)` | ERROR |
| `python.security.os-popen` | `os.popen(...)` | ERROR |
| `python.security.subprocess-shell` | `subprocess.call(...)` | WARNING |
| `python.security.subprocess-run` | `subprocess.run(...)` | WARNING |
| `python.security.subprocess-popen` | `subprocess.Popen(...)` | WARNING |
| `python.security.pickle-load` | `pickle.load(...)` | ERROR |
| `python.security.pickle-loads` | `pickle.loads(...)` | ERROR |
| `python.security.yaml-load` | `yaml.load(...)` | ERROR |
| `python.security.marshal-loads` | `marshal.loads(...)` | ERROR |
| `python.security.shelve-open` | `shelve.open(...)` | WARNING |
| `python.security.hashlib-md5` | `hashlib.md5(...)` | WARNING |
| `python.security.hashlib-sha1` | `hashlib.sha1(...)` | WARNING |
| `python.security.compile-usage` | `compile(...)` | WARNING |
| `python.security.input-python2` | `input(...)` | INFO |
| `python.security.ssl-no-verify` | `ssl._create_unverified_context(...)` | ERROR |
| `python.security.requests-no-verify` | `requests.get(...)` | INFO |
| `python.security.tempfile-mktemp` | `tempfile.mktemp(...)` | WARNING |
| `python.security.hardcoded-secret` | `$KEY = "..."` | WARNING |

### JavaScript (`rules/javascript-security.yaml`)

13 rules covering:

| Rule ID | Pattern | Severity |
|---------|---------|----------|
| `javascript.security.eval-usage` | `eval(...)` | ERROR |
| `javascript.security.function-constructor` | `Function(...)` | ERROR |
| `javascript.security.settimeout-string` | `setTimeout(...)` | WARNING |
| `javascript.security.setinterval-string` | `setInterval(...)` | WARNING |
| `javascript.security.exec-usage` | `exec(...)` | ERROR |
| `javascript.security.child-process-exec` | `child_process.exec(...)` | ERROR |
| `javascript.security.child-process-spawn` | `child_process.spawn(...)` | WARNING |
| `javascript.security.innerhtml` | `document.write(...)` | ERROR |
| `javascript.security.json-parse` | `JSON.parse(...)` | INFO |
| `javascript.security.crypto-createhash-md5` | `crypto.createHash(...)` | INFO |
| `javascript.security.http-createserver` | `http.createServer(...)` | INFO |
| `javascript.security.hardcoded-secret` | `$KEY = "..."` | WARNING |
| `javascript.security.process-exit` | `process.exit(...)` | INFO |

### Universal (`rules/universal-security.yaml`)

3 cross-language rules that apply to both Python and JavaScript.

## Writing custom rules

Rules are Semgrep-compatible YAML:

```yaml
rules:
  - id: my-org.no-console-log
    pattern: console.log(...)
    message: Remove console.log before deploying
    languages: [javascript]
    severity: WARNING
```

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier |
| `pattern` | string | Code pattern to match |
| `message` | string | Human-readable finding message |
| `languages` | list | `[python]`, `[javascript]`, or both |
| `severity` | enum | `ERROR`, `WARNING`, or `INFO` |

### Pattern syntax

Three pattern types are supported:

**Simple call** — matches any call to the named function:
```yaml
pattern: eval(...)
```

**Member call** — matches a method call on a specific object:
```yaml
pattern: subprocess.call(...)
```

**Assignment** — matches variable assignment with a literal value:
```yaml
pattern: $KEY = "..."
```

`...` means "any arguments" in call patterns and "any string" in assignments.

`$KEY` is a metavariable — matches any identifier.

### Naming convention

```
<scope>.<category>.<name>
```

Examples:
- `python.security.eval-usage`
- `javascript.security.hardcoded-secret`
- `my-org.style.no-console-log`

### Testing your rules

Add a trigger line to a test fixture and verify:

```bash
echo 'eval("hello")' > /tmp/test.py
zent scan /tmp/test.py --config my-rules.yaml
```
