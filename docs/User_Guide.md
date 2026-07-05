# User Guide

## Overview

Cybersecurity Alert Dashboard is a local Windows security assessment tool. It scans the current PC, summarizes security posture, displays findings, and provides allowlisted remediation actions for selected Windows hardening settings.

The application runs locally. It does not upload scan data to the cloud.

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- Administrator rights for full remediation coverage

## Running the dashboard

### Standard mode

Double-click:

```text
Run_Dashboard.bat
```

Use this mode to view the dashboard and run checks that do not require elevated privileges.

### Administrator mode

Right-click or double-click:

```text
Run_Dashboard_Admin.bat
```

Use this mode for full scan and remediation coverage. Some checks can only collect evidence or apply fixes when the Python process is elevated.

## Running a scan

1. Launch the dashboard.
2. Click **Run test on PC**.
3. Review the score, category results, and finding list.
4. Open the detailed analysis tab for evidence and recommendations.

## Applying remediation

The dashboard supports two remediation paths:

- **Fix issue**: applies a single allowlisted remediation.
- **Fix all detected issues**: applies only actions included in the safe bulk-remediation list.

Some changes require a restart, sign-out, network reconnect, or service restart before the scan evidence changes.

## Exporting a report

Use the report export option in the dashboard to save a JSON report. The report can be used for documentation, comparison, or audit review.

## Audit log

The dashboard writes local activity to:

```text
logs/audit.log
```

The log records scan and remediation events.

## Troubleshooting

### The browser does not open

Run the dashboard manually from a terminal:

```text
python cyber_dashboard.py
```

Then open the local address printed in the terminal.

### Some fixes are blocked

Run the dashboard in administrator mode. Some Windows registry, firewall, service, and audit policy changes require elevation.

### A finding does not disappear after remediation

Restart the PC or reconnect to the network, then run the scan again. Some Windows settings are not reflected immediately.

### Security software flags the script

Review the source code before running. The tool modifies Windows hardening settings, so some security products may treat it cautiously.
