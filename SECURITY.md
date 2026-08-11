# Security Policy

## Supported Versions

`0.1.0-alpha.1` is a prerelease and does not yet receive a long-term support guarantee. Security fixes are applied to the latest commit on `main` until the first stable support policy is published.

## Reporting A Vulnerability

Do not open a public issue containing credentials, tenant data, exploit details, or an undisclosed vulnerability. Use GitHub's private vulnerability reporting for `aiadjacent/reltio-cli` when available. If private reporting is unavailable, open a minimal public issue requesting a private maintainer contact without including sensitive details.

Include:

- affected commit/version and platform;
- attack prerequisites and impact;
- minimal reproduction using synthetic data;
- whether any real secret or tenant may have been exposed;
- suggested mitigation, if known.

Revoke exposed Reltio credentials immediately through the appropriate administrative process. Clearing the CLI cache with `reltio auth logout` does not revoke a server-side token.

## Security Boundaries

Read [the threat model](docs/threat-model.md). No debug mode may disable TLS verification, target validation, protected-header controls, or core secret redaction.
