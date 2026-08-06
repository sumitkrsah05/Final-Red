# Technical Report — eng-agent-localhost

## Findings

| Severity | Priority | Risk | Detection | Title | Asset | CVEs | ATT&CK | Sources |
|---|---|---|---|---|---|---|---|---|
| medium | medium | 53.0 | UNKNOWN | Prometheus Metrics - Detect | http://localhost:3000/metrics | - | - | nuclei |
| low | low | 30.0 | UNKNOWN | Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE | localhost* | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Server leaks inodes via ETags, header found with file /, fields: 0xW/26af 0x19fd0cae31d | localhost/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Uncommon header 'access-control-allow-origin' found, with contents: * | localhost/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Uncommon header 'feature-policy' found, with contents: payment 'self' | localhost/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Uncommon header 'x-content-type-options' found, with contents: nosniff | localhost/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN | localhost/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Uncommon header 'x-recruiting' found, with contents: /#/jobs | localhost/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200) | localhost//ftp/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | /ftp/: This might be interesting... | localhost/ftp/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | /public/: This might be interesting... | localhost/public/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | "robots.txt" contains 1 entry which should be manually viewed. | localhost/robots.txt | - | - | nikto |
| info | info | 10.0 | UNKNOWN | Add DOM EventListener - Detection | http://localhost:3000 | - | T1189 | nuclei |
| info | info | 10.0 | UNKNOWN | Deprecated Feature-Policy Header - Detection | http://localhost:3000 | - | T1046 | nuclei |
| info | info | 10.0 | UNKNOWN | FingerprintHub Technology Fingerprint | http://localhost:3000 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | HTTP Missing Security Headers | http://localhost:3000 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | OWASP Juice Shop | http://localhost:3000 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Wappalyzer Technology Detection | http://localhost:3000 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Public Swagger API - Detect | http://localhost:3000/api-docs/swagger.json | - | - | nuclei |

## Candidate attack paths

- `localhost:3000` (risk 53.0): T1189(UNKNOWN) → T1046(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)
- `localhost*` (risk 30.0): ?(UNKNOWN)
- `localhost` (risk 30.0): ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)