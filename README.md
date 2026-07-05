# Cybersecurity Alert Dashboard v10

Local Windows security assessment dashboard built with Python, HTML, CSS, and JavaScript.

## What it does

- Runs a localhost-only Python API.
- Launches a browser-based dashboard.
- Scans the current Windows PC for security posture issues.
- Calculates a cumulative risk score.
- Shows pass / warn / fail findings with evidence and recommendations.
- Provides individual **Fix issue** actions.
- Provides **Fix all detected issues** for free, allowlisted remediations.
- Exports a JSON report.
- Writes a local audit log in `logs/audit.log`.

## v10 additions

v10 expands the project past basic endpoint checks into a broader workstation-hardening assessment:

- Fixed false-positive detection for Teredo/ISATAP/6to4 tunneling.
- Added WinRM Basic auth, unencrypted traffic, and remote shell policy checks.
- Added RDP NLA, TLS security layer, drive redirection, and clipboard redirection hardening.
- Added automatic checks/fixes for Remote Desktop and Remote Assistance firewall rule groups.
- Added administrative share and null-session share/pipe hardening.
- Added Attachment Manager antivirus scanning enforcement.
- Added Search/Cortana/web suggestion privacy checks.
- Added CEIP, feedback notification, app telemetry, inventory, and content-delivery hardening.
- Added Wi-Fi Sense/OEM auto-connect hardening.
- Added input personalization / implicit text and ink collection hardening.
- Added UAC prompt behavior and installer detection hardening.
- Added RPC unauthenticated client and authenticated endpoint-resolution hardening.
- Added Safe DLL search order and SEH overwrite protection checks.
- Added Windows Media sharing, Xbox service, Geolocation service, and Windows Installer user-install checks.

## How to run

1. Extract the ZIP.
2. Double-click `Run_Dashboard_Admin.bat` for full scan/fix coverage.
3. Click **Run test on PC**.
4. Click **Fix all detected issues** or select individual fixes.
5. Re-run the scan to verify the score and findings.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator rights for system-level remediations

## Design limits

- No third-party Python packages.
- No external downloads.
- No cloud upload.
- No paid upgrade recommendations.
- No arbitrary command execution.
- The dashboard uses only local Windows APIs, registry policy settings, `netsh`, `auditpol`, and allowlisted PowerShell commands.

Some fixes may require sign-out, network reconnect, or restart before scan evidence changes.


## v10.1 Connectivity Safety Hotfix

Removed the automatic check/fix that disabled `WinHttpAutoProxySvc`. On Windows 11, disabling this service can prevent `Wcmsvc` and `WlanSvc` from starting, which can break Wi-Fi/internet connectivity. The dashboard no longer flags this service as risky and the Fix All action no longer attempts to disable it.


## v10.2 Usability and Connectivity Update

- Removed browser proxy auto-detection remediation from checks and Fix All to avoid interfering with networks that rely on automatic proxy discovery.
- Kept `WinHttpAutoProxySvc` untouched; the dashboard does not disable this service.
- Added three dashboard tabs: Analysis Overview, Full Analysis, and Visuals.
- Added category pass-rate bars that show green pass percentage and red remaining percentage.
- Added compact remediation priorities and visual scan statistics.
- Removed generated cache files from the package.
