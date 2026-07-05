# Security Model

## Goals

- Keep all scan data local.
- Avoid cloud uploads and remote dependencies.
- Prevent arbitrary command execution from the dashboard UI.
- Make remediation actions reviewable in source code.
- Preserve an audit trail for scan and fix activity.

## Local server controls

The backend binds to `127.0.0.1` and is intended for same-machine use only. The server uses a per-session bearer token and validates expected request patterns.

## Frontend controls

The frontend avoids remote scripts and does not rely on external libraries. Finding data is rendered through safe DOM operations rather than direct HTML injection.

## Remediation controls

Remediation requests use action IDs. The backend resolves those action IDs to predefined Python, PowerShell, Registry, `netsh`, or `auditpol` actions. The browser cannot submit arbitrary shell commands.

## Limitations

This is a local security assessment and hardening utility. It is not an EDR, antivirus, vulnerability scanner, SIEM, or enterprise endpoint management product.
