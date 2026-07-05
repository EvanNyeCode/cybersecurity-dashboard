# Architecture

## High-level design

Cybersecurity Alert Dashboard uses a local-first architecture. The Python backend serves a browser dashboard and exposes a small localhost API for scanning, remediation, report export, and shutdown.

```text
Browser dashboard
HTML / CSS / JavaScript
        |
        v
Local HTTP API
127.0.0.1 + per-session token
        |
        v
Python assessment engine
        |
        +--> Windows Registry
        +--> PowerShell
        +--> auditpol
        +--> netsh
        +--> Windows services
        +--> local system information
```

## Main components

### `cyber_dashboard.py`

Primary backend application. It starts the local server, runs the scan engine, calculates scores, executes allowlisted fixes, writes the audit log, and serves the frontend.

### `frontend/index.html`

Main dashboard interface.

### `frontend/assets/app.js`

Client-side dashboard behavior, including scan requests, findings rendering, fix requests, tab logic, chart-like visual summaries, and report export interaction.

### `frontend/assets/styles.css`

Dashboard styling and visual layout.

### `logs/audit.log`

Local audit trail for scan and remediation events.

## Security model

The application is designed to reduce risk from the local web interface:

- Binds only to `127.0.0.1`.
- Uses a random per-session bearer token.
- Rejects unexpected Host and Origin patterns.
- Uses small JSON request bodies.
- Avoids remote libraries and cloud services.
- Uses a strict frontend content security policy.
- Does not expose arbitrary command execution.
- Executes only static, allowlisted remediation actions.

## Scan model

A scan collects local Windows security posture evidence and converts it into structured findings. Each finding can include:

- ID
- Title
- Category
- Severity
- Status
- Evidence
- Recommendation
- Optional remediation action

The scoring engine weights findings by severity and produces an overall score, status counts, severity counts, category summaries, and remediation priorities.

## Remediation model

Remediation actions are stored as explicit fix definitions. The frontend can request a fix by action ID, but the backend maps that ID to a static implementation. This prevents the browser from sending arbitrary commands.

Bulk remediation uses a stricter safe-action list so that higher-risk or context-dependent changes are not automatically applied without review.
