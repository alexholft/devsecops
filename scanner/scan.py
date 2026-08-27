#!/usr/bin/env python3
"""
Lightweight orchestrator for static scans using Semgrep, Bandit and npm audit.
- Runs semgrep for multi-language rules (recommended for OWASP/CWE coverage)
- Runs Bandit for Python code
- Runs `npm audit --json` when package.json is present
Aggregates JSON outputs into results/ and prints a short summary.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

RESULTS_DIR = Path("results")


def run_cmd(cmd, cwd=None):
    try:
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
        return {"returncode": res.returncode, "stdout": res.stdout, "stderr": res.stderr}
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": f"{cmd[0]}: not found"}


def run_semgrep(target):
    out = run_cmd(["semgrep", "--config", "p/ci", "--json", "-o", "semgrep-results.json", str(target)])
    # semgrep already wrote file if installed; try to load
    results = {}
    path = Path("semgrep-results.json")
    if path.exists():
        try:
            results = json.loads(path.read_text())
        except Exception:
            results = {"error": "failed to parse semgrep output"}
    else:
        results = {"error": "semgrep not run or output missing", "exec": out}
    return results


def run_bandit(target):
    out = run_cmd(["bandit", "-r", str(target), "-f", "json", "-o", "bandit-results.json"])
    path = Path("bandit-results.json")
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {"error": "failed to parse bandit output"}
    else:
        return {"error": "bandit not run or output missing", "exec": out}


def run_npm_audit(target):
    pkg = Path(target) / "package.json"
    if not pkg.exists():
        return {"skipped": "no package.json"}
    out = run_cmd(["npm", "audit", "--json"], cwd=target)
    if out["returncode"] == 0 or out["stdout"]:
        try:
            return json.loads(out["stdout"] or out["stderr"])
        except Exception:
            return {"error": "failed to parse npm audit output", "exec": out}
    return {"error": "npm audit failed", "exec": out}


def detect_languages(target):
    exts = set()
    for p in Path(target).rglob("*"):
        if p.is_file():
            exts.add(p.suffix.lower())
    langs = set()
    if ".py" in exts:
        langs.add("python")
    if ".js" in exts or ".jsx" in exts or ".ts" in exts or ".tsx" in exts:
        langs.add("javascript/typescript")
    if ".java" in exts:
        langs.add("java")
    if ".go" in exts:
        langs.add("go")
    if ".cs" in exts:
        langs.add("c#")
    if ".cpp" in exts or ".c" in exts or ".h" in exts:
        langs.add("c/c++")
    return sorted(langs)


def save_json(name, data):
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / name
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def summarize_semgrep(sem):
    if not sem or "error" in sem:
        return str(sem.get("error", sem)) if isinstance(sem, dict) else str(sem)
    matches = sem.get("results") or []
    return f"semgrep findings: {len(matches)}"


def main():
    parser = argparse.ArgumentParser(description="Orchestrate static scans (Semgrep, Bandit, npm audit)")
    parser.add_argument("target", nargs="?", default=".", help="Path to scan")
    parser.add_argument("--skip-bandit", action="store_true")
    parser.add_argument("--skip-semgrep", action="store_true")
    parser.add_argument("--skip-npm", action="store_true")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print("Target path does not exist", file=sys.stderr)
        sys.exit(2)

    print(f"Scanning {target}...")
    langs = detect_languages(target)
    print("Detected languages:", ", ".join(langs) or "none")

    aggregate = {"target": str(target), "languages": langs, "results": {}}

    if not args.skip_semgrep:
        print("Running Semgrep (if installed) with p/ci rules)...")
        sem = run_semgrep(target)
        aggregate["results"]["semgrep"] = sem
        save_json("semgrep.json", sem)
        print(summarize_semgrep(sem))

    if not args.skip_bandit and ("python" in langs):
        print("Running Bandit for Python (if installed)...")
        band = run_bandit(target)
        aggregate["results"]["bandit"] = band
        save_json("bandit.json", band)
        print(f"Bandit: {band.get('metrics', {}).get('loc', 'unknown')} lines scanned" if isinstance(band, dict) else str(band))

    if not args.skip_npm:
        print("Running npm audit (if package.json present) ...")
        npm = run_npm_audit(str(target))
        aggregate["results"]["npm_audit"] = npm
        save_json("npm_audit.json", npm)
        print("npm audit: ", "skipped" if npm.get("skipped") else ("vulnerabilities reported" if npm and isinstance(npm, dict) and npm.get("vulnerabilities") else "no vulnerabilities or failed"))

    out = save_json("aggregate_results.json", aggregate)
    print(f"Saved aggregated results to {out}")
    print("Tip: use Semgrep rulesets for OWASP/CWE coverage. Semgrep rule metadata often includes CWE ids.")


if __name__ == "__main__":
    main()
