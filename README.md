# Cybersecurity Alert Dashboard v10.2

Local Windows security assessment and hardening dashboard built with Python, HTML, CSS, and JavaScript.

![Dashboard](assets/dashboard.png)

## Overview

Cybersecurity Alert Dashboard evaluates a Windows PC for security posture issues, calculates a risk score, presents findings in an interactive dashboard, and provides allowlisted remediation actions for selected hardening settings.

The project was built as a local-first desktop security tool. It does not upload scan results to the cloud and does not rely on third-party Python packages.

## Key features

- Localhost-only Python backend
- Browser-based HTML/CSS/JavaScript dashboard
- Windows security posture scan
- Weighted risk scoring
- Detailed findings with evidence and recommendations
- Individual remediation actions
- Safe bulk remediation workflow
- JSON report export
- Local audit logging
- Visual analysis tabs and category pass-rate bars

## Screenshots

### Dashboard overview

![Dashboard overview](assets/dashboard.png)

### Detailed findings

![Detailed findings](assets/findings.png)

### Visual analytics

![Visual analytics](assets/analytics.png)

### Remediation action log

![Action log](assets/action_log.png)

## Technologies

- Python
- HTML
- CSS
- JavaScript
- PowerShell
- Windows Registry
- `netsh`
- `auditpol`
- JSON

## Architecture

```text
Browser dashboard
        |
        v
Local HTTP API on 127.0.0.1
        |
        v
Python scan and remediation engine
        |
        +--> Windows Registry
        +--> PowerShell
        +--> Windows services
        +--> Firewall and audit policy tooling
```

## How to run

1. Install Python 3.10 or newer.
2. Clone or download this repository.
3. Run one of the launch scripts:

```text
Run_Dashboard.bat
Run_Dashboard_Admin.bat
```

Use administrator mode for full remediation coverage.

## Safety notes

- Runs locally on `127.0.0.1`.
- Uses a per-session bearer token.
- Uses static remediation allowlists.
- Does not accept arbitrary shell commands from the browser.
- Does not upload reports or telemetry.

## Documentation

- [User Guide](docs/User_Guide.md)
- [Architecture](docs/Architecture.md)
- [Checks and Remediations](docs/Checks_and_Remediations.md)
- [Security Model](docs/Security_Model.md)
- [Roadmap](ROADMAP.md)

## License

MIT License.
