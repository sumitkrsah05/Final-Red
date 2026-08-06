# Technical Report — eng-whitebox-demo

## Findings

| Severity | Priority | Risk | Detection | Title | Asset | CVEs | ATT&CK | Sources |
|---|---|---|---|---|---|---|---|---|
| medium | medium | 50.0 | UNKNOWN | python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected @ /home/sumit/Desktop/RedAgent/redAgent/safeguard/llm/client.py:103 | /home/sumit/Desktop/RedAgent/redAgent/safeguard/llm/client.py:103 | - | T1046 | semgrep |
| medium | medium | 50.0 | UNKNOWN | python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 @ /home/sumit/Desktop/RedAgent/redAgent/safeguard/tools/schema.py:63 | /home/sumit/Desktop/RedAgent/redAgent/safeguard/tools/schema.py:63 | - | - | semgrep |
| medium | medium | 50.0 | UNKNOWN | python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 @ /home/sumit/Desktop/RedAgent/redAgent/safeguard/tools/schema.py:88 | /home/sumit/Desktop/RedAgent/redAgent/safeguard/tools/schema.py:88 | - | - | semgrep |

## Candidate attack paths

- `` (risk 50.0): T1046(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)