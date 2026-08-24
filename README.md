# SafeHalt
**Emergency isolation and reversible file quarantine for Linux workstations.**

SafeHalt is a local command with two independent password. A single `safehalt trigger` prompt selects one of two responses.
|  Password  | Response |
|------------|----------|
|  Lockdown  | Isolate networking, lock local sessions and request a clean poweroff through detected host backends. |
| Quarantine | Atomically move allowlisted home subdirectories into a root-only quarantine, record a recovery manifest then perform a lockdown. |

SafeHalt detects Linux capabilities before activation. Distro identity is reported for packing and support, but it is never trusted as proof that a specific service or command exists.
This tool deliberately contains no file wipe, disk wipe, key destruction or recursive deletion feature. Quarantine is reversible and designed to fail closed when a target is unsafe.

### Why the name?
**SafeHalt** combines the intended outcome. Stop exposure quickly while keeping recovery possible.

## Cross-distro design
`safehalt doctor` reads `/etc/os-release`, inspects PID 1 and detects the available network, session and clean power-off mechanisms. Backend selection is capability based and fail-closed.
| Capability        | Supported backend choices in 0.3 |
| ----------------- | -------------------------------- |
| Network isolation | NetworkManager: isolated SafeHalt nftables table as a generic backend or fallback |
| Session locking   | the login1 interface exposed by systemd-logind or elogind |
| Clean power-off   | systemd, login1, OpenRC, runit, dinit, then the conventional `shutdown` interface |
| File quarantine   | same-filesystem atomic rename inside each account's declared home; distribution-independent |

SafeHalt refuses `trigger` before changing anything if a complete backend plan cannot be built. It does not guess based on a distribution name. 
Run:
```
safehalt doctor
safehalt doctor --json
```
“Linux” here means cross-distribution support with an explicit compatibility
report, not an untestable promise that every init system and desktop works.

## Security properties
- Two different scrypt-derived passwords; plaintext is never stored.
- A fresh sudo authentication is requested for every invocation.
- One prompt selects the emergency response without exposing the mode first.
- Activation is local and interactive; SSH and piped activation are rejected.
- Quarantine uses same-filesystem atomic renames, not copying or deletion.
- Every move is recorded in a root-only manifest and can be recovered.
- Symbolic links, mount points, complete homes, paths outside non-root account
  homes, unexpected ownership and overlapping targets are rejected.
- Homes are discovered through the system account database; `/home`,
  `/var/home`, `/srv/users` and multiple home roots do not require hardcoding.
- If a multi-path move fails, SafeHalt attempts rollback and records the result.
- The full action plan is preflighted before authentication or quarantine.
- The nftables fallback owns a uniquely named table and refuses to overwrite an
  unrecognized table with the same name.
Read [SECURITY_MODEL.md](SECURITY_MODEL.md) before relying on SafeHalt.

## Requirements
- Linux with at least one detected backend for each critical lockdown step.
- `loginctl` from systemd-logind or elogind for session locking in version 0.3.
- NetworkManager (`nmcli`) or nftables (`nft`) for network isolation.
- Python 3.11 or newer.
- A user authorized for `sudo`.
- Full-disk LUKS2 encryption is strongly recommended.

## Install
```
sudo ./install.sh
safehalt doctor
sudo safehalt setup
sudo safehalt status
```
`setup` asks for both emergency passwords and rejects identical values.

## Configure quarantine paths
Only select sensitive subdirectories. Do not try to select the complete home.
```
sudo safehalt paths add ~/Documents
sudo safehalt paths add ~/Pictures
sudo safehalt paths list
```
Remove an allowlisted path:
```
sudo safehalt paths remove ~/Pictures
```
SafeHalt creates a separate root-only quarantine beside each home root. It will
refuse activation if a target disappeared, changed identity, became a symbolic
link or cannot be moved atomically into its corresponding quarantine area.

## Test credentials
```
sudo safehalt test
```
This identifies the selected mode without cutting the network, moving files or
powering off.

## Trigger
Save open work before the first real test.
```
sudo safehalt trigger
```
After sudo and the emergency password there is no additional confirmation.

## Recover
| Use | Command |
|-----|---------|
| List Activations | ```sudo safehalt recovery list```|
| Restore one activation | ```sudo safehalt recovery run [Quarantine ID]``` |
| Remove SafeHalt isolation if power-off failed | ```sudo safehalt network-recover``` |

Both recovery operation require the quarantine password.

## Publish on GitHub
Replace `OWNER` in `pyproject.toml`, ensure the repository includes the complete [GPL-3.0-or-later](LICENSE) license text, and very that all the source files carry the appropriate license notice, then run:
```
git init
git add .
git commit -m "Initial SafeHalt 0.3.0 release under GPL-3.0-or-later"
git branch -M main
git remote add origin https://github.com/OWNER/safehalt.git
git push -u origin main
```
Before publishing:
- Set the repository license to GPL-3.0-or-later.
- Ensure the complete corresponding source code is available.
- Document third-party dependencies and their licenses.
- Create a GitHub security-advisory policy.
- Enable branch protection for main.
- Require pull requests and passing automated tests before merging.
- Preserve copyright and licensing notices in redistributed or modified versions.

## License
[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html). SafeHalt is free software: you may use, study, modify, and redistribute it. Distributed copies and derivative works must remain licensed under GPL-3.0-or-later, with their corresponding source code available under the same terms.
[Read here what is GPLv3 about](https://choosealicense.com/licenses/gpl-3.0/)
