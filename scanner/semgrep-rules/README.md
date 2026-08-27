OWASP/CWE Semgrep rules

This folder contains a small curated Semgrep ruleset that maps common anti-patterns to CWE identifiers and OWASP categories. Use it as a starting point and extend with project-specific rules.

Files:
- owasp-cwe.yml — Semgrep rules. Each rule includes `metadata.cwe` and `metadata.owasp` when applicable.

How to run:
  semgrep --config scanner/semgrep-rules/owasp-cwe.yml <path>

Notes and next steps:
- These rules are intentionally conservative examples. Tune patterns to reduce false positives and add tests.
- Convert rules to a ruleset collection or publish to semgrep registry for reuse.
- Add more mappings for dependency checks (CWE-937 etc.) and produce SARIF for CI ingestion.
