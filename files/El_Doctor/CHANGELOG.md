# Changelog

All notable changes to El Doctor. Versions follow [semantic versioning](https://semver.org/).

## [2.1.0] - unreleased (set the date when you tag v2.1.0)

### El Doctor Hub: one console for the whole fleet
- `eldoctor hub ...`: a central server in the same program. Agents enroll with a token (`eldoctor enroll`) and
  check in over mutual TLS using the hub's own certificate authority. The token carries the CA fingerprint, so there
  is no trust on first use, and agent keys never leave the machine.
- Fleet view (online / late / silent / revoked, version, mode, logged-in users). One alert queue, with triage
  (status, assignee, verdict, notes).
- Remote response on any computer (kill, suspend, resume, forensics, quarantine, block / unblock IP, set mode). It
  stays within the endpoint's allow-list and safety guards, runs at most once, and is audited on both sides.
- Fleet-wide threat intel: indicators added at the hub are detected and blocked by every agent.
- Hub detections: HUB-001 agent stopped reporting, HUB-002 agent back, HUB-003 endpoint audit trail rolled back or
  rewritten, HUB-004 revoked agent tried to connect. They are notified through the usual channels.
- Web console (no JavaScript, CSRF tokens, strict cookies and CSP). `eldoctor hub install-service` runs the hub as a
  hardened, unprivileged systemd service. The release smoke test runs a hub and enrolls an agent with every built
  executable. Guide: docs/HUB.md.

### Fixed (existing issues found while building the hub)
- Indicators added with `eldoctor intel add` were forgotten at the next restart (the CSV was never reloaded).

### Installers for non-technical users
- **Windows setup wizard** (`ElDoctor-Setup-<version>.exe`). Choose *all users* or *me only* (no administrator
  rights needed). Start-menu and desktop shortcuts. *Protect this computer around the clock* installs the background
  service, and a wizard page asks who manages El Doctor (the first administrator); the password never appears on a
  command line. Upgrades keep accounts and records. Uninstall from Settings → Apps; it asks whether to delete the
  records. Silent installation for IT departments.
- **macOS disk image** (`ElDoctor-<version>.dmg`) with `El Doctor.app`.
- **Linux packages** (`.deb`, `.rpm`): applications-menu entry and icon; upgrades restart the service, removal turns
  it off, `purge` deletes the records.
- `eldoctor install-service` / `uninstall-service [--purge | --stop-only]`: the whole-computer service, the same
  logic the installers use (Windows Scheduled Task as SYSTEM, Linux systemd).
- Clean stop before upgrades (`agent.shutdown`, for the agent's OS account or an administrator only), so an upgrade
  is not reported as a monitoring gap.
- An application icon for every platform; the GUI window uses it.
- Release workflow: every installer is installed and removed on its own operating system before publication
  (Windows including the protection service, the `.deb` on Ubuntu with systemd, the `.rpm` on AlmaLinux).

### Download and run
- **Standalone executables** for Linux, Windows and macOS: no Python needed. Extract and run `eldoctor`
  (Windows: `El Doctor.exe` for the desktop GUI). The Linux build runs on glibc 2.28+ (RHEL/Alma/Rocky 8+,
  Ubuntu 20.04+, Debian 10+). Every release ships SHA-256 checksums, a CycloneDX SBOM and build provenance.
  See [INSTALL.md](INSTALL.md).
- `eldoctor doctor`: checks an installation and says how to fix each problem (read-only, no login).
- Started without a terminal (double-click), El Doctor opens the desktop GUI instead of waiting for input.
- Service installers (`install.sh`, `install.ps1`) install the standalone executable when it is next to them,
  and **upgrade in place**: an existing installation keeps its users, keys and records and is not re-registered.
- Dependencies pinned with hashes (`requirements.lock`); a single version number (`eldoctor/__init__.py`).

### User-activity record (forensics and triage)
- Who is logged in, which applications each person runs, and which files they create, edit, delete (including
  moves to the Trash), rename, open or download. Every record says who did it and how that is known (kernel,
  open handle, command line, inferred, unknown).
- Survives shutdowns and reboots, sealed in the signed audit chain. Files deleted while El Doctor was not running
  are found at the next start; boots, unclean shutdowns and monitoring gaps are recorded.
- Data-wipe incidents (ED-ACT-001/002) are e-mailed to the registered administrators with the user responsible
  and a zipped CSV of every affected file and folder; the persistent outbox retries across restarts.
- `eldoctor activity now | list | sessions | status | export | reports` and a *User activity* tab in the GUI
  (analyst and admin roles).
- Sigma rules for wipe tools (shred, dd/wipefs/mkfs on devices, rm -rf of homes, SDelete, cipher /w, format);
  playbook `pb-data-destruction`; auditd / Sysmon file events.

### Accounts
- `eldoctor passwd` (change your password), `eldoctor users reset-password USER` (admin), and
  `eldoctor recover-admin`: a forgotten admin password can be reset by root / the agent's OS account - no more
  deleting the database. Recoveries are critical audit events.

### Operations
- Size-based rotation of `metrics.csv`, `alerts.jsonl`, `audit.jsonl` and `activity.jsonl`
  (`storage.rotate_mb`, `storage.rotate_keep`); rotated audit files still verify offline.
- Evidence retention (`storage.evidence_retention_days`, default 90) and hourly database upkeep.
- Log file `<data folder>/logs/eldoctor.log` (rotated): agent start/stop, failures, notification errors.

### Fixed
- Any CLI invocation (even `--help`) created the data folder.
- Re-running an installer on an installed machine registered an extra (viewer) account.
- The Windows installer could not replace program files held open by the running agent.

## [2.0.0]

- El Doctor rebuilt as the `eldoctor` package: detection (heuristics, Sigma, IOC feeds, YARA, MITRE ATT&CK),
  SOAR-style playbooks with monitor / interactive / enforce modes and safety guards, notifications, mandatory
  registration with roles, agent-side RBAC behind a local authenticated API, a forward-secure signed audit trail
  forwarded to the SIEM, deployment bundles for Windows, Linux, Docker, Kubernetes, AWS, Azure and GCP.
