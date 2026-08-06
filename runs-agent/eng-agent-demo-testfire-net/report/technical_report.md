# Technical Report — eng-agent-demo-testfire-net

## Findings

| Severity | Priority | Risk | Detection | Title | Asset | CVEs | ATT&CK | Sources |
|---|---|---|---|---|---|---|---|---|
| low | low | 30.0 | UNKNOWN | DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.a | demo.testfire.net | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS | demo.testfire.net/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Cookie JSESSIONID created without the httponly flag | demo.testfire.net/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server. | demo.testfire.net/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server. | demo.testfire.net/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | The anti-clickjacking X-Frame-Options header is not present. | demo.testfire.net/ | - | - | nikto |
| low | low | 30.0 | UNKNOWN | Expired SSL Certificate | demo.testfire.net:443 | - | - | nuclei |
| low | low | 30.0 | UNKNOWN | Weak Cipher Suites Detection | demo.testfire.net:443 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Deprecated TLS Detection | demo.testfire.net:443 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Detect SSL Certificate Issuer | demo.testfire.net:443 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | SSL DNS Names | demo.testfire.net:443 | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | TLS Version - Detect | demo.testfire.net:443 | - | T1046 | nuclei |
| info | info | 10.0 | UNKNOWN | Apache Detection | https://demo.testfire.net | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | HTTP Missing Security Headers | https://demo.testfire.net | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Missing Cookie SameSite Strict | https://demo.testfire.net | - | T1203 | nuclei |
| info | info | 10.0 | UNKNOWN | WAF Detection | https://demo.testfire.net | - | - | nuclei |
| info | info | 10.0 | UNKNOWN | Public Swagger API - Detect | https://demo.testfire.net/swagger/index.html | - | - | nuclei |

## Candidate attack paths

- `demo.testfire.net` (risk 30.0): T1203(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)
- `demo.testfire.net:443` (risk 30.0): T1046(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN) → ?(UNKNOWN)