# Security Policy

ChatGPT Gateway MCP Nyan sits on a security-sensitive boundary between agent clients and execution resources. Please do not publish exploit details, credentials, production topology or active tokens in public issues.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available. If private reporting is unavailable, open a minimal issue that contains no exploit payload, secret or sensitive infrastructure detail and request a private contact path.

Include:

- affected version or commit;
- affected component;
- prerequisite permissions or network position;
- expected versus observed authorization behavior;
- a minimal reproduction that does not include real credentials;
- whether the issue may have caused an unknown side-effect outcome.

## Security expectations

A production deployment should, at minimum:

- disable development authentication;
- use a real identity provider and validate issuer, audience and scopes;
- store credentials outside Git and outside browser-visible state;
- pin SSH host keys rather than relying on development `accept-new` behavior;
- keep the SSH command profile `restricted` unless broader execution is explicitly required;
- keep Docker access disabled unless delegating the Docker socket is intentional;
- keep private-network and insecure HTTP MCP upstream access disabled unless explicitly approved;
- terminate TLS at a trusted ingress;
- use PostgreSQL with controlled migrations and backups;
- monitor audit, command-session and approval records;
- reconcile unknown outcomes after timeouts instead of blindly retrying side-effecting actions.

## Public source boundary

This public repository intentionally excludes private deployment configuration, production host inventories, private CI/CD topology, private acceptance evidence, internal-only dependency artifacts and credentials.

If you discover material that appears to violate that boundary, report it as a security issue even if it is not immediately exploitable.
