# Security Policy

HTLogin is an active security testing tool. Only run it against systems you
own or have explicit permission to test.

## Reporting a vulnerability in HTLogin

Please do not open a public issue for a vulnerability that could expose users
of HTLogin. Use GitHub's private vulnerability reporting for this repository,
or contact the maintainer privately with:

- affected version and commit
- reproducible steps or a minimal proof of concept
- impact and suggested mitigation

## Safe operation

Use `--safe-mode` for passive inspection. Active credential, injection,
enumeration, and rate-limit probes require an authorized test scope. The
`--max-requests` option limits requests sent through the main HTTP client per
target.
