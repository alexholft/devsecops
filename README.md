OWASP/CWE Scanner (starter)

This repository contains a small Python orchestrator that runs multiple scanners to detect vulnerabilities in source code according to OWASP/CWE concepts.

Quick start
1. Create a virtualenv and install optional tools:
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   pip install semgrep bandit   # optional but recommended

2. Run the scanner (scans current dir by default):
   python scanner\scan.py .

Notes
- Semgrep covers many languages and has rule metadata that often includes CWE ids. Use the `p/ci` ruleset as a starting point or add custom Semgrep rules.
- Bandit is used for Python-specific checks.
- npm audit is invoked if a package.json is present for dependency vulnerability checks.
- For Java and other ecosystems, consider adding OWASP Dependency-Check, Trivy or Snyk integrations.

Next steps (recommended)
- Add CI job to install semgrep and run scanner, fail on high severity findings.
- Add custom Semgrep rules mapping to specific CWE identifiers for your app.
- Produce SARIF output for code scanning integrations.
