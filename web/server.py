#!/usr/bin/env python3
"""Zentinel Web Scanner — paste a GitHub URL, get a security dashboard.

Clones the repo, runs zent scan with all rule files, streams findings
back as JSON for the frontend dashboard.

Usage:
    pip install fastapi uvicorn
    python3 web/server.py

    Then open http://localhost:8000
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Zentinel Scanner")

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
ZENT_BIN = PROJECT_ROOT / "zig-out" / "bin" / "zent"
RULES_DIR = PROJECT_ROOT / "rules"

# Language detection
LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
}

RULE_FILES = {
    "python": [
        RULES_DIR / "python-security.yaml",
        RULES_DIR / "community" / "python-community.yaml",
    ],
    "javascript": [
        RULES_DIR / "javascript-security.yaml",
        RULES_DIR / "community" / "javascript-community.yaml",
    ],
    "typescript": [
        RULES_DIR / "typescript-security.yaml",
        RULES_DIR / "community" / "typescript-community.yaml",
    ],
    "go": [
        RULES_DIR / "go-security.yaml",
        RULES_DIR / "community" / "go-community.yaml",
    ],
}


class ScanRequest(BaseModel):
    repo_url: str


class Finding(BaseModel):
    file: str
    line: int
    col: int
    message: str
    severity: str
    rule_id: str


class ScanResult(BaseModel):
    repo: str
    files_scanned: int
    findings: list[Finding]
    duration_ms: float
    languages: dict[str, int]
    severity_counts: dict[str, int]
    top_rules: list[dict]
    tier_counts: dict[str, int]


def clone_repo(url: str, dest: str) -> bool:
    """Shallow clone a GitHub repo."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, dest],
            capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def find_scannable_files(repo_dir: str) -> dict[str, list[str]]:
    """Find all files grouped by language."""
    by_lang: dict[str, list[str]] = {}
    repo_path = Path(repo_dir)

    for f in repo_path.rglob("*"):
        if not f.is_file():
            continue
        # Skip hidden dirs, node_modules, vendor, etc.
        parts = f.relative_to(repo_path).parts
        if any(p.startswith(".") or p in ("node_modules", "vendor", "venv", "__pycache__", "dist", "build") for p in parts):
            continue
        ext = f.suffix
        lang = LANG_MAP.get(ext)
        if lang:
            by_lang.setdefault(lang, []).append(str(f))

    return by_lang


def run_scan(files: list[str], rule_file: Path) -> list[Finding]:
    """Run zent scan on a list of files with a rule config."""
    if not files or not rule_file.exists():
        return []

    try:
        cmd = [str(ZENT_BIN), "scan"] + files + ["--config", str(rule_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        findings = []
        for line in result.stdout.splitlines():
            # Parse: file:line:col: message [SEVERITY] (rule-id)
            import re
            m = re.match(r'^(.+?):(\d+):(\d+): (.+?) \[(\w+)\] \((.+?)\)(?:\s*\[cross-file\])?$', line)
            if m:
                findings.append(Finding(
                    file=m.group(1),
                    line=int(m.group(2)),
                    col=int(m.group(3)),
                    message=m.group(4),
                    severity=m.group(5),
                    rule_id=m.group(6),
                ))
        return findings
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def classify_tier(rule_id: str) -> str:
    """Classify a finding's tier from the rule ID."""
    if "taint" in rule_id or "crossfile" in rule_id:
        return "Tier 2/3"
    if any(k in rule_id for k in ("shell-true", "fstring", "new-md5", "new-sha1", "precise", "template")):
        return "Tier 1"
    return "Tier 0"


@app.post("/api/scan", response_model=ScanResult)
async def scan_repo(req: ScanRequest):
    """Clone a GitHub repo and scan it."""
    url = req.repo_url.strip()

    # Validate URL
    if not url.startswith("https://github.com/"):
        raise HTTPException(400, "Only GitHub HTTPS URLs are supported")

    # Extract repo name
    parts = url.rstrip("/").split("/")
    repo_name = f"{parts[-2]}/{parts[-1]}" if len(parts) >= 2 else url

    if not ZENT_BIN.exists():
        raise HTTPException(500, "zent binary not found. Run: zig build -Doptimize=ReleaseFast")

    tmpdir = tempfile.mkdtemp(prefix="zentinel-scan-")
    try:
        start = time.time()

        # Clone
        repo_dir = os.path.join(tmpdir, "repo")
        if not clone_repo(url, repo_dir):
            raise HTTPException(400, f"Failed to clone {url}")

        # Find files
        files_by_lang = find_scannable_files(repo_dir)
        if not files_by_lang:
            raise HTTPException(400, "No scannable files found (Python/JS/TS/Go)")

        # Scan each language
        all_findings: list[Finding] = []
        lang_file_counts = {}

        for lang, files in files_by_lang.items():
            lang_file_counts[lang] = len(files)
            for rule_file in RULE_FILES.get(lang, []):
                findings = run_scan(files, rule_file)
                all_findings.extend(findings)

        duration = (time.time() - start) * 1000

        # Strip tmpdir prefix from file paths
        for f in all_findings:
            f.file = f.file.replace(repo_dir + "/", "")

        # Aggregate stats
        severity_counts = {}
        rule_counts = {}
        tier_counts = {}

        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
            tier = classify_tier(f.rule_id)
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        # Top rules
        top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:15]
        top_rules = [{"rule": r, "count": c} for r, c in top_rules]

        total_files = sum(lang_file_counts.values())

        return ScanResult(
            repo=repo_name,
            files_scanned=total_files,
            findings=all_findings,
            duration_ms=round(duration, 1),
            languages=lang_file_counts,
            severity_counts=severity_counts,
            top_rules=top_rules,
            tier_counts=tier_counts,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# Serve frontend
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    return (Path(__file__).parent / "templates" / "index.html").read_text()


if __name__ == "__main__":
    import uvicorn
    print(f"Zentinel Web Scanner")
    print(f"  Binary: {ZENT_BIN}")
    print(f"  Rules:  {RULES_DIR}")
    print(f"  Open:   http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
