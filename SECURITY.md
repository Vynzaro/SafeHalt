# Security policy

## Supported versions
Only the newest tagged SafeHalt release receives security fixes during the alpha
stage.

## Reporting a vulnerability
Do not open a public issue for vulnerabilities involving authentication,
path validation, privilege boundaries, quarantine escape or recovery failure.
Use the repository's **Private vulnerability reporting** feature under
Security → Advisories.

Include the affected version, output of `safehalt doctor --json`, reproduction
steps and expected impact. Remove passwords, personal file names and manifest
contents.

## Non-negotiable boundary
SafeHalt does not accept contributions adding irreversible deletion, disk wipe,
encryption-key destruction, remote activation or covert execution.
