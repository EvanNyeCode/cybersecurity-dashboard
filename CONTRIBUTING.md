# Contributing

This project is a local Windows security assessment dashboard. Contributions should preserve its safety model: local-only execution, no arbitrary command execution, no cloud upload, and remediation through explicit allowlists.

## Development setup

1. Fork the repository.
2. Clone your fork.
3. Use Python 3.10 or newer on Windows 10/11.
4. Run the dashboard with `Run_Dashboard.bat` for normal mode or `Run_Dashboard_Admin.bat` for full remediation testing.

## Contribution guidelines

- Keep the dashboard local-only.
- Do not add remote tracking, telemetry, cloud uploads, or third-party scripts.
- Do not add remediation actions that accept raw user input as shell commands.
- Every remediation action must be explicit, reviewable, and allowlisted.
- Prefer readable code over clever shortcuts.
- Document any Windows setting that a check or fix modifies.

## Adding a new check

When adding a check, include:

- Finding title
- Category
- Severity
- Evidence
- Recommendation
- Optional remediation action ID

## Adding a new fix

When adding a fix, ensure that:

- It is safe to run on a personal workstation.
- It does not require external downloads.
- It does not execute arbitrary user-provided commands.
- It is included in the safe fix-all set only when the action is low-risk and reversible or clearly documented.

## Pull request checklist

- [ ] The dashboard still starts locally on `127.0.0.1`.
- [ ] Scan runs without crashing.
- [ ] Existing buttons still work.
- [ ] New findings include evidence and a recommendation.
- [ ] New fixes are statically allowlisted.
- [ ] Documentation is updated when behavior changes.
