# Technical Report — eng-api-white_box-d1704bb3

## Findings

| Severity | Priority | Risk | Detection | Title | Asset | CVEs | ATT&CK | Sources |
|---|---|---|---|---|---|---|---|---|
| medium | medium | 50.0 | UNKNOWN | python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2 @ /home/sumit/Desktop/swarn/src/swarn_analyst/nodes/reporting.py:133 | /home/sumit/Desktop/swarn/src/swarn_analyst/nodes/reporting.py:133 | - | T1189, T1046 | semgrep |
| medium | medium | 50.0 | UNKNOWN | python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2 @ /home/sumit/Desktop/swarn/src/swarn_analyst/prompts/__init__.py:17 | /home/sumit/Desktop/swarn/src/swarn_analyst/prompts/__init__.py:17 | - | T1189 | semgrep |
| medium | medium | 50.0 | UNKNOWN | CVE-2026-71433 in langgraph-checkpoint-sqlite | /home/sumit/Desktop/swarn:langgraph-checkpoint-sqlite | CVE-2026-71433 | T1190 | trivy |

## Candidate attack paths

- `` (risk 50.0): T1189(UNKNOWN) → T1189(UNKNOWN) → T1190(UNKNOWN)