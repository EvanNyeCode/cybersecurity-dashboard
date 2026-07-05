# Changelog

## v10.2

- Removed browser proxy auto-detection remediation to avoid disrupting networks that rely on automatic proxy discovery.
- Kept `WinHttpAutoProxySvc` untouched after connectivity testing showed that disabling it can break Wi-Fi or Windows network services on some Windows 11 systems.
- Added the dashboard tabs `Analysis Overview`, `Full Analysis`, and `Visuals`.
- Added category pass-rate bars showing green pass percentage and red remaining percentage.
- Added compact remediation priorities and visual scan statistics.
- Removed generated cache files from the public package.

## v10.1

- Removed automatic disabling of `WinHttpAutoProxySvc`.
- Prevented the `Fix All` workflow from applying the unsafe WinHTTP Auto Proxy Service change.
- Added a connectivity safety note to the README.

## v10.0

- Expanded assessment coverage beyond basic endpoint checks into broader workstation-hardening checks.
- Added checks and remediation logic for WinRM, Remote Desktop, Remote Assistance firewall rules, administrative shares, null-session restrictions, Attachment Manager scanning, Search/Cortana privacy, telemetry, Wi-Fi Sense/OEM auto-connect, UAC behavior, RPC hardening, Safe DLL search order, SEH overwrite protection, Windows Media sharing, Xbox services, Geolocation service, and Windows Installer policy.
- Added JSON report export and local audit logging.
- Added allowlisted individual remediation and safe bulk remediation.
