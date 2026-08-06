# Technical Report — eng-api-black_box-5a53fa42

## Findings

| Severity | Priority | Risk | Detection | Title | Asset | CVEs | ATT&CK | Sources |
|---|---|---|---|---|---|---|---|---|
| info | info | 10.0 | UNKNOWN | HTTP Missing Security Headers | http://localhost:5174 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | README.md file disclosure | http://localhost:5174/README.md | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Visual Studio Code jsconfig.json - Detect | http://localhost:5174/jsconfig.json | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | NPM package.json Disclosure | http://localhost:5174/package-lock.json | - | T1190 | nuclei |
| info | info | 10.0 | UNKNOWN | NPM package.json Disclosure | http://localhost:5174/package.json | - | T1190 | nuclei |

## Candidate attack paths

- `localhost:5174` (risk 10.0): T1190(UNKNOWN) → T1190(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)