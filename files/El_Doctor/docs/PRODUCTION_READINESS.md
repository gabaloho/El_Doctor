# El Doctor: production-readiness review

**Bottom line:** El Doctor is a working, well-tested **prototype / pilot** of an endpoint detection and
automated-response tool. On Linux it does everything requested:

* 15/15 live attack scenarios detected and contained;
* 204 automated tests;
* 29/29 requirement checks in `scripts/verify_requirements.py`.

It is **not yet production ready**. The trust-boundary blocker (P0-1) is now resolved: the agent is
the only component that touches the data and decides permissions, and the audit trail is
tamper-evident and leaves the host. The remaining blockers are the untested privileged and Windows
paths, false-positive risk in automatic kill mode, and the missing operational plumbing (CI,
updates, retention, fleet management). A tool that kills processes
on its own needs a higher bar than a monitoring dashboard: a wrong kill is an outage, and a
bypassable approval is a privilege-escalation path.

### Status after release 2.1.0 ("download and run")

| Item | Status |
|---|---|
| P1-5 delivery engineering | **Resolved, except signing.** Standalone executables built by `packaging/build_release.py` and smoke-tested *as built* (doctor, registration, bundled rules/playbooks, a live agent recording file activity, audit verification, deployment bundle). CI (`.github/workflows/ci.yml`: lint + Linux 3.9-3.13 + Windows/macOS) and release workflow (Linux in AlmaLinux 8 with a glibc 2.28 gate, Windows, macOS; SBOM, checksums, build provenance). Dependencies pinned with hashes (`requirements.lock`), single-source version, no runtime `pip install` in standalone builds. Open: code-signing certificates (the hook `ELDOCTOR_SIGN_CMD` exists). |
| P1-4 retention | **Mostly resolved.** Size rotation of metrics.csv / alerts.jsonl / audit.jsonl / activity.jsonl, evidence retention (90 days), activity retention option, hourly WAL checkpoint + optimize. Open: the alert / action tables still grow (they are ledgered; pruning them needs a ledger-aware design like `prune_activity`). |
| P1-3 account lifecycle | **Partly resolved.** Password change, admin reset, local recovery (`recover-admin`, root / agent account only, critical audit event). Open: MFA, per-source rate limiting, session listing. |
| P1-6 robustness | **Partly resolved.** Rotating log file (`<data>/logs/eldoctor.log`), persistent outbox for admin reports, monitoring-gap detection (ED-ACT-005). Open: response in worker threads, persistent queue for *all* notifications, SIEM heartbeat. |
| Installers for non-technical users | **Built; Linux .deb verified here, the rest in CI.** Windows setup wizard (Inno Setup: all users / me only, optional round-the-clock protection with the first administrator entered in the wizard, upgrades in place, uninstall that asks before deleting records, silent mode), macOS disk image, Linux .deb / .rpm with a menu entry. The shared service logic (`eldoctor install-service`) is unit-tested with the Windows calls recorded. The .deb went through dpkg's install / upgrade / remove / purge here. The Windows wizard, the Windows service, the .rpm, the .dmg and the .deb + systemd path run for the first time in the release workflow, which installs and removes each of them on its own OS. Open: code signing / notarization (SmartScreen and Gatekeeper warn until then). |
| P1-7 central management | **Resolved for visibility, triage, response and intel** (El Doctor Hub, docs/HUB.md): enrollment, mutual TLS, fleet view, alert queue with triage, remote response bounded by each endpoint, fleet threat intel, web console, hardened hub service. Open: distribution of Sigma rules / playbooks / config, central approvals of interactive-mode requests, multi-hub / external database for very large fleets, automatic certificate renewal. |
| P1-6 heartbeat | **Resolved with the hub**: HUB-001 when an agent stops reporting, HUB-003 when its audit trail is rolled back or rewritten. |
| P0-2 Windows | **Still open, now measurable.** Windows CI test job and the Windows release build + smoke test exist, but have never run (no Windows here). The test job is `continue-on-error` until its first green run. |
| P0-3 privileged paths | Still open. New since 2.0: the installers upgrade in place (checked statically, `bash -n`); the Linux installer has not run as root here. |
| P0-4 false positives | Unchanged: CPU-only kills happen only in `enforce` mode, which is opt-in (admin). |

Priorities:
* **P0**: blocks any production use.
* **P1**: required before general availability.
* **P2**: should fix.

---

## P0: blockers

### P0-1. Permissions are enforced by the user interfaces, not by the agent — **RESOLVED**
**Original evidence:** a self-registered *viewer* ("attacker_user") has no approve permission. She wrote
`status='approved', decided_by='admin1'` straight into `eldoctor.db`. The agent then **killed the
process**, and the audit trail showed the approval as coming from *admin1*. Roles were checked in
`cli.py` / `gui.py`; the agent (`PlaybookEngine.process_approvals`) trusted whatever was in the
database, and the audit table lived in that same, editable database.

**What was done** (README section 6b). The three recommended steps, plus integrity checks on
everything the agent acts on:

1. **The agent owns the database.** The CLI, TUI and GUI no longer open it; R7.3 checks this
   statically. `eldoctor service` locks the data folder to the service account at every start and
   repairs loosened permissions (`eldoctor/lockdown.py`):
   * POSIX: 0700 folder, 0600 files, owner root, no symlinks, umask 0077.
   * Windows: `icacls`, SYSTEM only.

   The systemd unit adds `StateDirectory` 0700 and a `RuntimeDirectory` for the socket.
2. **Local authenticated API** (`eldoctor/api/`):
   * Unix socket with `SO_PEERCRED` / `LOCAL_PEERCRED`, or a Windows named pipe with a restrictive
     DACL and `GetNamedPipeClientProcessId`.
   * The client also verifies the server's identity.
   * Sessions are **stateless HS256 JWTs** bound to the OS uid that logged in. They are revoked by
     `jti` (logout) or token version (role change, disable). The role is always re-read from the
     sealed user record.
   * One method→permission table in the agent is the **only** RBAC decision point. Denials are
     audited (`api_denied`).
   * Optional OS-level policy: `api.allowed_os_users/groups`, `api.admin_os_groups`, socket group.
     Creating the first admin is restricted to the agent's OS account or root.
3. **Tamper-evident audit trail** (`eldoctor/integrity.py`, `eldoctor/storage.py`, `eldoctor/siem.py`):
   * Every record has `seq` and `prev_hash`, a public SHA-256 `hash`, and an agent `mac`.
   * A sealed head pointer keeps truncation visible even after new appends.
   * The chain is verified at start, periodically and with `eldoctor audit verify`.
   * Every record is **forwarded in real time** to the SIEM: syslog UDP/TCP/TLS in CEF, RFC 5424 or
     JSON; signed webhook; JSONL. Delivery is ordered and at-least-once with persisted cursors.
     `eldoctor audit verify-export` checks an off-host copy without any key.
4. **Nothing the agent acts on is trusted because it is in a row.**
   * Approval requests and decisions, user records, IP blocks and quarantine records are HMAC-sealed.
   * Before executing an approval, the agent checks both seals and the matching chained audit record.
     It checks that the approver *currently* holds `approve`, and that the approval was not already
     executed (replay).
   * Manual responses carry only a PID and start time; the agent resolves the process itself.
   * Any violation is refused, marked `rejected` and raised as a critical **ED-INT-001** incident
     with a forced notification.

**Verification:**
* `tests/test_integrity.py`: the exact P0-1 attack, copied-MAC, inserted-row and retargeted requests,
  an approver demoted before execution, replay, role edits, an emptied user table, forged blocks,
  tampered quarantine, five audit attacks, truncation followed by new appends, a recomputed chain
  without the key, adoption of a pre-integrity database, and removed metadata.
* `tests/test_api.py`: RBAC for every method × role, JWT binding/forgery/expiry/revocation, peer
  policies, the real Unix socket, SIEM delivery, outage recovery and lockdown. The CLI is also run
  against a running `eldoctor service`.
* Verifier checks R7.1–R7.7.
* `scripts/tamper_demo.py` replays the finding against a live lab agent: **10/10 refused / detected**.
* The 15-scenario enforce lab still reaches **15/15** on the new architecture.

**Follow-up (turn 8): the two limits left by the first fix are closed.**
* *"Whoever can read the agent key can forge seals"* is resolved by **forward-secure, publicly
  verifiable signatures**:
  * every audit record is signed with a one-time Ed25519 key and commits to the next key; the used
    key is destroyed after the commit;
  * stealing every file therefore gives no power over anything written before the theft;
  * rebuilding the chain changes the genesis fingerprint, which can be pinned;
  * signatures verify with public keys only, so the SIEM copy is checkable without any secret.
* *"Alerts and the actions log are not sealed"* is resolved by a **signed ledger**:
  * every write to alerts, actions, users, IP blocks, quarantine records and approval requests records
    the row's digest in the signed chain;
  * the agent checks rows against it before acting, so a recomputed HMAC seal is no longer enough;
  * `audit verify` reports edited, planted and deleted rows; listings show per-row integrity.
* Verification: `tests/test_forward_secure.py` (14 tests, attacker holding every key file),
  verifier R8.1–R8.3, and `scripts/tamper_demo.py` steps 6–8 against a live agent (**15/15**).

**Residual risk (accepted):**
* An attacker who controls the host *while the agent runs* (root / the service account) can append
  new records with the current one-time key, i.e. act as the agent. Root can also kill processes or
  stop El Doctor directly, so no on-host design prevents this. They cannot alter history, and whatever
  they append is chained after it and forwarded to the SIEM in real time.
* Used keys are overwritten and unlinked. Remnants can survive on copy-on-write or SSD storage; use
  full-disk encryption.
* Not executed here: the Windows named-pipe transport and ACL lockdown (no Windows; see P0-2), and
  multi-account socket use against a root service (single unprivileged account in the sandbox).
  Cross-account logic is tested through the same handler with kernel-style peer identities.
* There is no per-peer login rate limiting yet (lockout is per account; see P1-3).

### P0-2. Windows, the primary "desktop" target, has never been run
**Evidence:** all live testing ran on Ubuntu. Never executed:
* `install.ps1` and the Scheduled Task service;
* Event Log collection via `wevtutil`, and the Sysmon / 4688 mappings (unit-tested with sample XML only);
* the `netsh` firewall backend;
* quarantining a locked `.exe`;
* `windows-curses`;
* the Tk GUI on Windows fonts and HiDPI scaling.

The Windows collector also *polls* `wevtutil` per channel every cycle, which spawns about 2
processes per second.

**Why it matters here:** you asked for a Windows desktop deployment option, and Windows desktops
are where users will meet El Doctor first.

**What to do:**
* Add a Windows CI job (GitHub Actions `windows-latest`) running the test suite.
* Write a manual acceptance plan on Windows 10/11 with Sysmon (SwiftOnSecurity or Olaf Hartong
  config), covering install / uninstall, service mode, desktop GUI, approvals, kill, quarantine and
  firewall block.
* Replace `wevtutil` polling with `EvtSubscribe` (pywin32) push subscriptions.

### P0-3. The privileged response paths have never executed
**Evidence:** the sandbox had no root. So the following were generated and syntax-checked, but
never run:
* iptables / nftables / netsh blocking;
* the live auditd exec collector;
* the systemd unit's capability set;
* the Docker Compose stack, the Kubernetes DaemonSet, and cloud-init / Terraform.

Block-IP was only exercised in its *app-level* fallback, which kills a process **after** it has
connected; it is reactive, not preventive.

**Why it matters here:** production deployments (service mode, servers, cloud, Kubernetes) run
privileged, so this is where real containment happens.

**What to do:**
* Add CI integration stages in disposable VMs/containers: run `scripts/lab.sh enforce` as root, with
  real firewall rules and auditd.
* `docker compose up` with the generated bundle.
* Deploy the DaemonSet to a `kind` cluster.
* Boot one cloud VM per provider from the generated cloud-init.

### P0-4. False-positive containment in enforce mode
**Evidence (observed during this project):**
* the enforce-mode agent killed a legitimate **pytest run** (CPU rule);
* it flagged a **pip build** as a CPU hog;
* it flagged the sandbox's own command runner as fileless malware (correct detection, wrong target);
* the *name-based* IOC list includes generic names (`sysupdate`, `networkservice`).

Renaming a binary evades name IOCs, while a legitimate tool that happens to share a name gets killed.

**Why it matters here:** you asked for automatic kills of resource-hungry processes. CPU usage alone
is weak evidence: it can't tell a build, video encode or database from a miner. One wrong kill on a
customer server is an incident, and it destroys trust in automated response.

**What to do:**
* Enforce mode auto-kills only on **high-confidence** evidence: IOC hash/IP, critical Sigma, YARA, or
  several correlated signals (for example CPU + stratum port + miner name).
* Pure resource abuse defaults to `renice` + approval (`max_mode: interactive` on `pb-resource-hog`).
* Add a learning / baseline period per host.
* Manage allow-lists from the GUI/CLI, not only in YAML.
* Add a false-positive review queue, and prune generic names from `miner_names`.

---

## P1: required before general availability

### P1-1. Detection coverage and content quality
* Process polling (1–2 s) misses short-lived commands; this was demonstrated with `bash -c "...; exec"`.
  The auditd (Linux) and Sysmon (Windows) paths that fix it were never run live. Recommend requiring
  Sysmon on Windows, and consider eBPF (Tetragon/Falco) on Linux.
* The Sigma engine implements a subset of the spec and was validated with El Doctor's 18 own rules,
  not the SigmaHQ repository. Measure: load SigmaHQ, report supported vs skipped, and compare
  verdicts with pySigma/Chainsaw on public datasets (EVTX-ATTACK-SAMPLES, OTRF Security-Datasets).
* Domain IOCs only match command lines: there is no DNS telemetry.

### P1-2. Threat-intel feeds are unverified against the real services
The real abuse.ch / Emerging Threats URLs were never fetched (no internet). Some abuse.ch endpoints now
require an Auth-Key (supported through the feed `headers`, but untested). Indicators never expire, and
there's no confidence scoring or feed-level allow-list. Add indicator expiry (TTL), auth keys, and
optionally MISP / OpenCTI.

### P1-3. Account lifecycle gaps
* No password change or reset (if the only admin forgets the password, the fix is deleting the database).
* The lockout can be abused to lock an admin out.
* No MFA.
* No listing of API keys or active sessions (sessions *can* be revoked: logout, `auth.logout_all`,
  role change, disabling the account).

Add `users passwd` / admin reset, an OS-admin-only recovery command, TOTP MFA for admins, and
rate-limiting per source.

### P1-4. No data retention
Measured in the sandbox: `metrics.csv` grows by **3.4 MB/day per host (~1.25 GB/year)** at the
default 2 s interval and is never rotated. The alert database, `alerts.jsonl` and the `evidence/`
folder also grow forever. Evidence files contain command lines, which may include secrets or
personal data. Add retention settings, log rotation, SQLite `VACUUM`, and evidence redaction/encryption.

### P1-5. Delivery engineering
* No CI.
* Tests ran manually in one Linux sandbox.
* Dependencies unpinned (`psutil>=5.9`).
* No lockfile, hashes or SBOM.
* Version number duplicated in `pyproject.toml` and `__init__.py`.
* The GUI runtime **pip-installs packages at runtime**, which is a supply-chain risk and fails offline.

Ship frozen, signed installers (PyInstaller/Briefcase → MSI / DMG / AppImage, `.deb` / `.rpm`), pinned
dependencies with hashes (`pip-compile --generate-hashes`), a CycloneDX SBOM, and a CI matrix of
Python 3.9–3.14 × Linux/Windows/macOS.

### P1-6. Agent robustness and self-protection
* A single loop does detection **and** response, so a kill's grace period (up to 3–5 s, observed)
  stalls detection for everything else.
* Notifications are queued in memory only and are lost if the agent crashes.
* No heartbeat: an attacker with root can stop El Doctor silently. There is only systemd/Task
  Scheduler restart.
* No structured log file of its own.

Move response to worker threads, add a persistent notification outbox, send a heartbeat to the SIEM
and alert on missed beats, and add rotated structured logging.

### P1-7. No central management for SOC / cloud fleets
Each host has its own users, playbooks, approvals and registration records. "Know the user and the
use case" only leaves the machine if `registration.webhook_url` is configured. For the SOC/MSSP and
cloud use cases you need:
* an enrollment server;
* policy and rule distribution;
* a fleet dashboard and central approvals.

Alternatively, position El Doctor as a sensor/responder for an existing console (Wazuh, Elastic,
TheHive + Shuffle); the notification channels are already there.

---

## P2: should fix

* **Privacy/compliance:** registration stores personal data (name, e-mail, organisation). The
  opt-in consent flag exists, but there's no privacy notice, export/delete, or retention policy
  (GDPR/CCPA).
* **Maintainability:** `ui/gui.py` (~1.8k lines) and `cli.py` (~900) should be split into modules.
  Add `mypy` and `ruff` to CI.
* **Usability:** Tk HiDPI scaling and fonts on Windows/macOS are untested, and allow-lists, retention
  and notification channels can't be managed from the GUI.
* **Network:** without privileges, block-IP is enforced only by killing the process after the
  connection. Document this clearly or require the privileged service for network containment.

---

## Fixed during this audit

| Finding | Fix |
|---|---|
| Outbound URLs accepted any scheme (`file:///etc/shadow` via a feed/webhook/registration URL) | `config.safe_url()`: http/https only, in notifications, feeds and registration |
| Windows event XML parsed with the standard-library parser (entity-expansion risk) | Input containing a DTD/ENTITY is rejected before parsing |
| Privileged tools (`netsh`, `iptables`, `wevtutil`, `journalctl`) resolved through `PATH` (hijack risk as root/SYSTEM) | `config.system_tool()`: absolute paths from trusted system directories only |
| Enforce-mode **tests and the verifier could act on any process on the machine** (they killed the sandbox's tool runner) | New `safety.only_descendants_of` response scope; tests and verifier are now hermetic |
| Config options that did nothing (`registration.require`, `detection.office_apps`, `notifications.include_actions`) | Removed (registration is always mandatory), or implemented (`include_actions`) |
| Lint findings (unused imports, closure-binding hazard in the Sigma engine) | Fixed; `ruff` clean on the F/E9/B/PLE rule sets |

## What is already solid

* Safety guards: parent chain, PID-reuse check, protected names/users, allow-lists, interpreter
  protection, IP rules, circuit breaker, response scope.
* No shell execution anywhere; actions use argument lists.
* Secrets come from environment variables, never from config files.
* Webhooks are HMAC-signed.
* Passwords use PBKDF2 with 600k iterations, with lockout. API keys are stored hashed, sessions are
  agent-signed JWTs bound to the OS account, and registration defaults to least privilege.
* Agent-side RBAC behind a peer-authenticated local API; forward-secure Ed25519-signed audit chain
  with a row ledger (alerts, actions, users, blocks, quarantine, approvals) and real-time SIEM
  forwarding.
* Single-instance lock and graceful SIGTERM shutdown.
* Correlation: one incident per entity.
* Hermetic tests across Python 3.12 and 3.14.
* A one-command verifier for every requirement.

## Suggested order of work

1. ~~**P0-1** (local API + agent-side authorization + tamper-evident audit)~~ - done, including
   forward-secure signatures and the row ledger. Optional hardening: TPM / OS-keystore storage of the
   current one-time key.
2. **P0-2 / P0-3** (Windows CI + acceptance run; privileged/container/cloud integration runs).
3. **P0-4** (high-confidence-only auto-kill, learning mode, allow-list management).
4. **P1-5** (CI, pinned dependencies, frozen signed installers), then P1-3, P1-4 and P1-6.
5. **P1-1 / P1-2 / P1-7** as the product moves from single hosts to fleets.
