# Technical Report — eng-api-black_box-2ca31f32

## Findings

| Severity | Priority | Risk | Detection | Title | Asset | CVEs | ATT&CK | Sources |
|---|---|---|---|---|---|---|---|---|
| info | info | 10.0 | UNKNOWN | HTTP Missing Security Headers | https://www.esds.co.in | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Wappalyzer Technology Detection | https://www.esds.co.in | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Weak HTTP Strict-Transport-Security - Detect | https://www.esds.co.in | - | T1046 | nuclei |
| info | info | 10.0 | UNKNOWN | Missing Subresource Integrity | https://www.esds.co.in/ | - | T1203 | nuclei |
| info | info | 10.0 | UNKNOWN | NPM package.json Disclosure | https://www.esds.co.in/package-lock.json | - | T1190 | nuclei |
| info | info | 10.0 | UNKNOWN | Detect SSL Certificate Issuer | www.esds.co.in:443 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | SSL DNS Names | www.esds.co.in:443 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | TLS Version - Detect | www.esds.co.in:443 | - | T1046 | nuclei |
| info | info | 10.0 | UNKNOWN | Wildcard TLS Certificate | www.esds.co.in:443 | - | - | nuclei |

## Candidate attack paths

- `www.esds.co.in` (risk 10.0): T1190(UNKNOWN) → T1203(UNKNOWN) → T1046(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)
- `www.esds.co.in:443` (risk 10.0): T1046(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)