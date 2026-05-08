# Security Policy

## Security goals

The Merovingian prioritises:

- protocol correctness
- secure defaults
- hardened deployment
- memory safety discipline
- encrypted-by-default policy
- auditable operation
- abuse resistance

## Supported versions

During pre-release development, only the latest development branch is supported.

## Reporting vulnerabilities

Do not report vulnerabilities publicly.

Until a dedicated security contact exists, open a private GitHub security advisory.

Reports should include:

- affected commit or branch
- reproduction steps
- impact assessment
- proof-of-concept if safe
- suggested remediation if available

## Security rules

- No custom cryptography.
- No raw owning pointers.
- References preferred over pointers.
- No parser without fuzz coverage.
- Security checks must remain enabled under load.
