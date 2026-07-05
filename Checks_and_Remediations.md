# Checks and Remediations

This dashboard evaluates Windows workstation hardening across multiple categories. The exact result depends on Windows edition, administrative privileges, available services, and local policy configuration.

## Major check groups

- Firewall configuration
- Microsoft Defender configuration
- Installed antivirus status
- Windows Update posture
- BitLocker, Secure Boot, and TPM indicators
- Remote access exposure
- Legacy protocols and services
- Identity and local account configuration
- Windows security settings
- Network exposure
- Hosts file, startup, and auditing
- Credential and network hardening
- Security service baselines
- Logging hardening
- Additional workstation hardening
- Extended hardening checks
- Enterprise-style hardening checks
- Deep Windows hardening checks

## Remediation philosophy

The remediation system is intentionally conservative. Fixes are designed to be explicit and allowlisted. `Fix all detected issues` should only apply actions that are considered reasonable for bulk remediation on a personal Windows workstation.

## Connectivity safety note

Version 10.2 avoids remediations that disable browser proxy auto-detection or `WinHttpAutoProxySvc`, because those settings can disrupt connectivity on networks that rely on automatic proxy discovery or Windows network service dependencies.

## Review before applying fixes

Some hardening changes may affect convenience features, including LAN discovery, Remote Desktop behavior, Remote Assistance, telemetry, media sharing, Xbox networking, geolocation, and search suggestions. Review findings before applying fixes on a production machine.
