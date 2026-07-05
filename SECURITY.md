# Security Notes

This project is intentionally designed as a local-only security dashboard.

## Local API controls

- Binds only to `127.0.0.1`.
- Uses a random per-session bearer token.
- Rejects invalid Origin / Host patterns.
- Accepts only small JSON request bodies.
- Only exposes scan, fix, fix-all, report, and shutdown endpoints.

## Frontend controls

- Strict Content Security Policy.
- No remote libraries.
- No inline JavaScript.
- No `eval`.
- No HTML injection rendering path.
- User-facing finding data is rendered with DOM text APIs.

## Remediation controls

- Every remediation action is statically allowlisted in `FIXES`.
- Fix-all uses the stricter `SAFE_FIX_ALL_ACTIONS` set.
- The browser cannot submit arbitrary commands.
- Python, PowerShell, and CMD calls are static and parameterless from user input.
- Admin-only actions are blocked unless the Python process is elevated.
- Audit log captures scan and remediation events.

## Scope decisions

- The dashboard avoids paid Windows Pro / BitLocker recommendations on Windows Home.
- The dashboard does not install software or download scripts.
- It prefers explicit local hardening settings over vague "open settings" actions.
- Some controls intentionally use policy registry keys so the result is auditable.

## Important operational note

This dashboard is a local endpoint assessment tool, not a replacement for enterprise endpoint management. Some hardening controls can affect convenience features such as LAN discovery, Xbox services, media sharing, search suggestions, telemetry, or RDP redirection. Review the code and selected actions before using it on a production PC.
