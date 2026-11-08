# El Doctor: requirements traceability (turn 1 → turn 8)

Every request made during the project, where it's implemented, how it's verified, and how far the
verification goes.

**Verify everything yourself:**

```bash
cd El_Doctor
python3 -m pip install -r requirements.txt        # psutil, PyYAML
python3 scripts/verify_requirements.py            # ~4 min: 29 behavioural checks (R1.1 ... R8.3)
python3 scripts/verify_requirements.py --full     # + full pytest suite + live 15-attack lab (~10 min, Linux)
```

Each check runs in a throwaway data folder and exercises the real feature: it kills real processes,
delivers real notifications over HTTP/SMTP/UDP, generates bundles, and starts the GUI runtime. Check
IDs in the table below match the verifier's output.

What the status column means:
* **Verified live**: ran for real in the sandbox against real processes and OS behaviour.
* **Verified, simulated input**: the code path ran for real, but its input was generated, because the
  real source doesn't exist in the sandbox (no sshd, journald, Windows or internet).
* **Built, not executable here**: the artefacts were generated and validated (syntax, YAML, contents)
  but can't run in this sandbox (Windows, Docker, Kubernetes, cloud, root).

## Turn 1: turn El Doctor into a security tool

| ID | Requirement | Implementation | Automated verification | Status |
|---|---|---|---|---|
| R1.1 | Rebuild as a package `eldoctor/` | `eldoctor/{collectors,detection,playbooks,response,notify,auth,deploy,ui}` | verifier R1.1 | Verified live |
| R1.2 | Keep the original tool (metrics, curses UI, CSV, email) | `collectors/metrics.py`, `ui/tui.py`, `notify/channels.py` (email), `el_doctor.py` | R1.2, `test_agent.py`, `test_agent::test_tui_renders_in_a_pty` | Verified live |
| R1.3 | Detection engine: heuristics + IOCs, mapped to MITRE ATT&CK | `detection/engine.py` (24 rules), `detection/ioc.py`, `mitre.py` | R1.3, `test_detection.py` | Verified live |
| R1.4 | Threat intelligence from free feeds (abuse.ch, Emerging Threats) | `detection/ioc.py:update_feeds`, `intel.feeds` in config | R1.4, lab `c2_beacon` / `ioc_hash` | Verified, simulated input (feeds served locally in the real abuse.ch formats; no internet in the sandbox) |
| R1.5 | Open-source detection content such as Sigma | `detection/sigma.py` (native engine), 18 rules in `data/rules/sigma`, YARA in `detection/yara_scan.py` | R1.5, `test_sigma.py` | Verified live (not yet run against the full SigmaHQ repository) |
| R1.6 | SOAR-style YAML playbooks | `playbooks/engine.py`, 9 playbooks in `data/playbooks` | R1.6, `test_response.py` | Verified live |
| R1.7 | Three modes: monitor, interactive approval, enforce | `PlaybookEngine.run`, sealed approvals in `storage.py`, TUI/GUI/CLI approve and deny through the agent API (`approvals.decide`) | R1.7, `interactive_demo.py`, `test_gui::test_interactive_approval_from_gui` | Verified live |
| R1.8 | Safety guards | `playbooks/safety.py` (parent chain, protected names/users, allow-lists, PID reuse, IP rules, interpreters, circuit breaker, response scope) | R1.8, `test_response.py` | Verified live |
| R1.9 | Actions: kill, suspend, quarantine, block-IP | `response/actions.py`, `response/firewall.py` | R1.9, lab | Kill/suspend/quarantine verified live. Block-IP verified at app level only; iptables/nftables/netsh need root/admin (built, not executable here) |
| R1.10 | Notifications: email, Slack, Teams, Discord, Shuffle/n8n/Tines, TheHive, syslog | `notify/channels.py`, `notify/dispatcher.py` | R1.10, `test_notify.py` | Verified live over real protocols against local endpoints. Not sent to real SaaS accounts |
| R1.11 | Mandatory registration with roles; know the user and use case | `auth/users.py`, agent-side gate in `api/server.py` (`authenticate` / `require`), CLI + GUI `AuthView` as API clients | R1.11, `test_auth_deploy_cli.py`, `test_gui.py` | Verified live |
| R1.12 | Deployment choice: Windows desktop, Linux, Docker, Kubernetes, cloud VMs | `deploy/generator.py`, CLI `deploy`, GUI Deploy tab, registration wizard | R1.12, `test_auth_deploy_cli::test_deploy_bundles` | Built, not executable here (no Windows/Docker/Kubernetes/cloud); the Linux source zip installed and ran in a clean venv |
| R1.13 | Real-time alerts + automatic kill of resource hogs / malicious processes | `agent.py`, `pb-resource-hog`, `pb-cryptominer`, etc. | R1.13, lab `scripts/lab.sh enforce` (15/15) | Verified live |
| R1.14 | Catch real system logs and alert | `collectors/logs.py` (files, journald, syslog receiver, auditd, Windows Event Log) | R1.14, lab `ssh_bruteforce` / `auth_log_file` | Verified, simulated input: real syslog protocol via `logger`, synthetic auth.log lines. The sandbox has no journald/sshd/auditd/Windows; the auditd and Windows parsers are unit-tested with real record formats |
| R1.15 | Run it in the sandbox and observe | `scripts/lab.sh`, `simulate_attacks.py`, `mock_receivers.py`, screenshots in `docs/` | T.2 (`--full`) | Verified live |
| R1.16 | Say where the work stopped | Summaries at the end of each turn; this document | – | Done |

## Turn 2: `python3 eldoctor` failed (`<frozen runpy>`)

| ID | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| R2.1 | Start with `python eldoctor` / `-m eldoctor` / `el_doctor.py` from any folder | `eldoctor/__main__.py`, `_bootstrap.fix_sys_path` | R2.1, `test_launch.py` | Verified live (Python 3.12 + 3.14) |
| R2.2 | Clear message when dependencies are missing; `requirements.txt` | `_bootstrap.ensure_dependencies`, `requirements.txt` | R2.2, `test_launch.py` | Verified live |

## Turn 3: GUI version

| ID | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| R3.1 | Desktop GUI with all functions; run it | `ui/gui.py` (9 tabs), `ui/launch.py`, `el_doctor_gui.pyw`, `eldoctor gui` | R3.1 (runs `tests/test_gui.py`); screenshots omitted from the public repo for privacy | Verified live on Linux (Tk 9). Not run on Windows |

## Turn 4: GUI would not start (no tkinter, no sudo)

| ID | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| R4.1 | Make the GUI run without installing python3-tk / without sudo | `ui/runtime.py` (finds a Tk-capable Python, builds a private runtime, relaunches) | R4.1, `test_gui_runtime.py` | Verified live from system Python 3.12 (no tkinter) |

## Turn 5: light mode

| ID | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| R5.1 | Light mode in addition to dark; user can switch | `THEMES`, `App.set_theme`, header button, Ctrl+T, Settings → Appearance, `--theme`, `gui.theme` | R5.1, `test_gui.py` (WCAG contrast, live switch, preference precedence) | Verified live |

## Turn 6: this audit

| ID | Requirement | Deliverable |
|---|---|---|
| R6.1 | Check that everything requested was done | this matrix + `scripts/verify_requirements.py` |
| R6.2 | Flag issues that block production readiness, and what to do | `docs/PRODUCTION_READINESS.md` |
| R6.3 | Explain how to verify | top of this document; `README.md` §9 |

## Turn 7: move the trust boundary into the agent (P0-1)

Request: a local authenticated API with OS-level peer credentials and session/JWT tokens. The CLI, GUI
and TUI become clients and all checks move into the agent. The database folder is locked to the service
account, and the audit log becomes tamper-evident (hash-chained records, real-time SIEM forwarding). RBAC
for approval and admin, which used to be checked only in the front ends, is now checked in the agent,
and forged approvals and audit records in the database are refused or detected.

| ID | Requirement | Implementation | Automated verification | Status |
|---|---|---|---|---|
| R7.1 | Local authenticated API, OS-level peer credentials | `api/transport.py` (AF_UNIX, framing, server/client identity checks), `api/peercred.py` (`SO_PEERCRED`, `LOCAL_PEERCRED`), `api/winpipe.py` (named pipe, DACL, client PID → token SID) | verifier R7.1; `test_api.py::test_unix_socket_with_kernel_peer_credentials`, `test_client_refuses_a_socket_served_by_another_account`, `test_second_agent_cannot_take_over_the_socket`, `test_one_account_cannot_exhaust_the_api_connections`, `test_allowed_os_accounts_policy`, `test_admin_os_group_policy` | Verified live on Linux (single OS account). Windows pipe: built, not executable here |
| R7.2 | Session tokens / JWT, stateless | `auth/tokens.py` (HS256, strict alg, aud/iss/exp/nbf), `jti` denylist + per-user `token_version` in `storage.py`/`users.py`, tokens bound to the peer uid (`ouid`) | verifier R7.2; `test_token_is_a_signed_jwt_bound_to_the_os_account`, `test_forged_expired_and_alg_none_tokens_are_refused`, `test_role_change_disable_and_logout_revoke_tokens` | Verified live |
| R7.3 | CLI, GUI, TUI become clients; every check in the agent (RBAC for approval + admin) | `api/server.py` (`METHODS` table → `AgentService.require`), `api/client.py` (`connect`, `ApiClient`, `RemoteAgent`), `cli.py`, `ui/tui.py`, `ui/gui.py` | verifier R7.3 (static: no DB access in front ends; viewer refused on every protected method); `test_agent_refuses_every_call_the_role_does_not_allow[viewer/analyst/admin]`, `test_cli_is_a_client_of_the_running_service`, `test_gui.py::test_viewer_is_read_only`, `test_gui_attaches_to_running_service` | Verified live |
| R7.4 | Database folder locked to the service account | `lockdown.py` (POSIX 0700/0600 + owner + no symlink; Windows `icacls` SYSTEM only), run by `eldoctor service`; systemd `StateDirectory`/`RuntimeDirectory`; installers | verifier R7.4; `test_lockdown_restricts_the_data_folder`; `test_cli_is_a_client_of_the_running_service` (modes after start) | Verified live (POSIX, unprivileged); root ownership change and Windows ACL not executable here |
| R7.5 | Tamper-evident audit log, hash-chained records | `integrity.py` (chain hash + agent MAC), `storage.py` (`audit`, sealed head, truncation-resistant append, `verify_audit`), periodic verification in `AgentService` | verifier R7.5; `test_audit_tampering_is_detected[5 attacks]`, `test_truncation_stays_visible_after_the_agent_writes_again`, `test_rewritten_chain_without_the_key_is_detected`, `test_agent_raises_chain_break_as_incident` | Verified live |
| R7.6 | Forward audit logs to the SIEM in real time | `siem.py` (syslog UDP/TCP/TLS × CEF/RFC 5424/JSON, signed webhook, JSONL; ordered, at-least-once, persisted cursors), `eldoctor audit verify-export` | verifier R7.6; `test_audit_forwarded_to_siem_in_real_time_and_verifiable`, `test_forwarding_survives_an_outage_without_losing_records`, `test_webhook_sink_is_signed`; lab: the mock SIEM received every audit record as CEF | Verified live against local TCP/UDP receivers; no real SIEM product in the sandbox |
| R7.7 | Forged approvals / audit trails in the DB no longer work (safety valve + accountability) | sealed approvals + decision audit record + approver re-check (`Store.verify_approval`, `PlaybookEngine.process_approvals`), sealed users, blocks, quarantine; ED-INT-001 incident | verifier R7.7; `test_integrity.py` (21 tests); `scripts/tamper_demo.py` against a live agent (10/10) | Verified live |

## Turn 8: close the two documented limits, and prepare the review

Request: fix "anyone who can read the agent's key can forge seals" and "alerts and the actions log are
not sealed", then tell a reviewer what to check for turns 7 and 8 (`docs/REVIEW_GUIDE.md`).

| ID | Requirement | Implementation | Automated verification | Status |
|---|---|---|---|---|
| R8.1 | Key theft must not allow forging or rewriting the audit trail; verification without secrets | `integrity.py` (`SigningChain`: one-time Ed25519 key per record, `next_pub` commitment, destroy after commit; `verify_records` v2: signatures + key continuity; genesis fingerprint), `storage.py:audit` (crash-safe key handling, head pointer carries `next_pub`), `siem.py` (v2 fields in JSON/CEF/RFC 5424, `verify_export` with `--genesis` pin), `audit.genesis_fingerprint` | verifier R8.1; `test_forward_secure.py::test_every_record_is_signed_and_used_keys_are_destroyed`, `test_stolen_keys_cannot_rewrite_history`, `test_keeping_the_committed_key_without_its_private_half_fails_the_signature`, `test_rebuilding_the_whole_chain_changes_the_genesis`, `test_a_lost_signing_key_is_an_incident`, `test_siem_copy_is_verifiable_without_any_secret`, `test_crash_between_commit_and_key_destruction_is_harmless`, `test_database_from_the_first_chain_version_is_upgraded`; `tamper_demo.py` step 7 | Verified live |
| R8.2 | Alerts and the actions log tamper-evident | `storage.py` ledger (`_ledger_write` on every write, `ledger_state`, `verify_ledger`), `alerts.list` / `alerts.get` / `actions.list` integrity, CLI `integrity` column, GUI alert detail | verifier R8.2; `test_alerts_and_actions_are_tamper_evident`, `test_api_and_cli_show_row_integrity`; `tamper_demo.py` step 8 | Verified live |
| R8.3 | State the agent acts on cannot be forged with a stolen HMAC key | `user_row_ok`, `active_blocks`, `quarantine_record`, `verify_approval` / `decide_approval` require the ledger; the long-running agent uses a fully verified index (`enable_verified_ledger`) | verifier R8.3; `test_hmac_key_holder_cannot_promote_a_user`, `test_key_holder_cannot_rewrite_the_ledger_record_either`, `test_blocks_quarantine_and_approval_requests_need_the_ledger`; `tamper_demo.py` step 6 | Verified live |
| R8.4 | Reviewer guidance for both turns | `docs/REVIEW_GUIDE.md` | – | Done |

## Turn 9: user-activity record for forensics and triage

> "Capture the current logged-in user, running applications, and files opened / downloaded / deleted / edited by the
> user while the system was on. Records must transcend shutdowns and reboots. Even when data is wiped or deleted,
> the user who did it and the affected files and folders must be recorded and sent to the registered admin's e-mail."

| ID | Requirement | Implementation | Automated verification | Status |
|---|---|---|---|---|
| R9.1 | Current logged-in user(s), login / logout history | `activity/sessions.py` (`SessionTracker` on utmp / WTS, session types, `read_wtmp` for logins while El Doctor was off), sshd / sudo / Windows 4624-4634 events (`monitor._log_event`), API `activity.now` / `activity.sessions`, CLI `activity now` / `sessions`, GUI *User activity* tab | `test_logins_logouts_and_applications`, `test_wtmp_logins_while_el_doctor_was_off`, `test_activity_api_rbac_and_export_audit` | Verified, simulated input (no utmp sessions in the sandbox; wtmp parsed from glibc-format records) |
| R9.2 | Running applications per user | `monitor._apps` (app_start / app_stop / app_running inventory: command line, parent, SHA-256, cwd, terminal, run time), `activity.now` | `test_logins_logouts_and_applications` (real child process) | Verified live |
| R9.3 | Files created / edited / deleted / renamed / opened / downloaded | `activity/fswatch.py` (inotify via ctypes), `activity/scanner.py` (folder scans: Windows / macOS / start-up), `monitor._ingest` coalescing (atomic saves, partial downloads, Trash moves, secure-deletion chains), download origin (xdg xattrs / Mark of the Web) + SHA-256, GTK recently-used, Sysmon 11/23/26/15 + Security 4663 + auditd file records (`collectors/logs.py`) | `test_file_activity_is_recorded_and_classified`, `test_polling_backend_used_on_windows_and_macos`, `test_secure_deletion_is_one_record_under_the_original_name`, `test_windows_sysmon_and_security_file_events`, `test_auditd_file_records_name_the_login_user_behind_sudo` | Verified live on Linux (inotify, polling); auditd / Sysmon: simulated input |
| R9.4 | *Who* did it | `activity/attribution.py`: kernel (auditd auid / Sysmon) > open handle > command line (incl. globs / braces in `sh -c`) > inferred (labelled) > unknown; every record carries `attribution` | `test_who_deleted_it_command_line_and_open_handle_attribution`, `test_unexpanded_globs_and_braces_attribute_wrapped_wipes`, `test_inference_is_labelled_as_a_lead_not_proof` | Verified live (cmdline, handle); kernel: simulated input |
| R9.5 | Records survive shutdowns and reboots, and cannot be silently altered | SQLite `activity` table committed at once, row digests taken in the inserting transaction, sealed in the signed audit chain (immediately for high-value rows, else every `seal_interval`; crash leftovers sealed as `recovered`) (`add_activity`, `seal_activity`, `seal_recovered_activity`, `verify_activity`, `prune_activity`), persisted `file_index` + start-up comparison (offline changes), boot id / heartbeat (`system_boot`, `system_shutdown` clean / unclean, `monitoring_gap` + ED-ACT-005), open wipe incident recovered after a crash | `test_activity_rows_are_sealed_in_the_signed_chain`, `test_retention_prunes_whole_sealed_batches_and_stays_verifiable`, `test_deletions_while_el_doctor_was_not_running_are_found_and_reported`, `test_unclean_stop_is_a_monitoring_gap_alert`, `test_wipe_incident_interrupted_by_a_crash_is_reported_after_restart`, `test_deferred_seal_still_catches_edits_made_before_the_seal`, `test_rows_left_unsealed_by_a_crash_are_flagged_then_sealed_as_recovered`, `test_routine_activity_does_not_grow_the_signed_chain_every_cycle` | Verified live (restart with a new process on the same database; boot change simulated) |
| R9.6 | Data wipe: record the user + every affected file/folder, e-mail the registered admins | `activity/wipe.py` (burst → incident, bounded memory), ED-ACT-001 / 002 / 003, `pb-data-destruction` (evidence + suspend, per mode), `activity/report.py` (recipients = verified admin accounts + extras; zipped CSV of every item; persistent outbox retried across restarts), Sigma wipe-tool rules (shred, dd/wipefs/mkfs on devices, rm -rf of homes, SDelete, cipher /w, format, rd /s /q) | `test_mass_deletion_alerts_and_emails_the_registered_admins` (real SMTP), `test_offline_wipe_raises_alert_and_report_persists_until_smtp_exists`, `test_agent_runs_the_data_destruction_playbook_on_the_wiper`, `test_wipe_tool_sigma_rules`, `test_deleting_el_doctors_evidence_is_an_incident` | Verified live |
| R9.7 | Safe on hostile input; access control | FIFO / symlink-safe reads (`safe_open`), no-DTD XML, CSV-injection neutralised, header-safe subjects, `forensics` permission (analyst, admin), exports audited | `test_a_fifo_or_symlink_posing_as_a_download_cannot_stall_or_leak`, `test_report_attachment_and_subject_are_neutralised`, `test_activity_api_rbac_and_export_audit`, `test_cli_activity_export` | Verified live |
| R9.8 | Deployment | Linux bundle: auditd deletion/rename rules for /home and /root, inotify watch limit; Windows bundle: Sysmon file-event guidance; README section 5b | `test_deploy_bundles` | Built, not executable here (root / Windows) |

## Turn 11: an installer for people who are not developers

> "A non-technical user cannot run our application: package it in an installer, a downloadable file they can
> execute, as an alternative way of installation."

| ID | Requirement | Implementation | Automated verification | Status |
|---|---|---|---|---|
| R11.1 | Windows: one downloadable file that installs El Doctor | `packaging/windows/eldoctor.iss` (setup wizard: all users / me only, shortcuts, optional round-the-clock protection + administrator page, upgrade, uninstall, silent mode), built by `packaging/build_release.py` | `test_setup_wizard_script_is_consistent` (static); release workflow: silent per-user install/uninstall + all-users install with the service, login to it, uninstall | Built, not executable here (Windows) |
| R11.2 | Whole-computer protection without a terminal | `eldoctor/installer.py` + `eldoctor install-service / uninstall-service [--purge | --stop-only]`; clean stop (`agent.shutdown`); Windows registry marker so reinstalls find kept records; GUI waits for a starting service | `test_windows_install_registers_the_admin_then_upgrades_in_place`, `test_windows_uninstall_keeps_records_and_a_reinstall_finds_them`, `test_linux_install_and_remove`, `test_agent_shutdown_only_for_the_agents_account`, `test_installer_stops_a_running_agent_cleanly` | Verified (Linux live; Windows logic with recorded OS calls) |
| R11.3 | Mac and Linux installers | `El Doctor.app` + `.dmg` (spec BUNDLE, `hdiutil`), `packaging/linux_packages.py` (.deb in pure Python, .rpm via rpmbuild), menu entry, icons | `test_deb_package_is_accepted_by_dpkg`, `test_desktop_entry_and_icons`, `test_spec_builds_icons_and_the_mac_app`; dpkg install/upgrade/remove/purge in an alternate root; release workflow: .rpm installed in AlmaLinux, .deb via apt + systemd on Ubuntu, .dmg verified on macOS | .deb verified live; .rpm / .dmg built in CI |
| R11.4 | The developer / portable ways keep working | archives, wheel, `install.sh` / `install.ps1` unchanged in behaviour | full test suite, release smoke test | Verified live |

## Turn 12: what is critical for security operations - the fleet console

> "Which other issue is critical to make this application more powerful for security operations? Proceed with it."

Finding: every agent was an island (no fleet view, no shared alert queue, no coordinated response, and a killed or
wiped agent went unnoticed). Implemented: El Doctor Hub.

| ID | Requirement | Implementation | Automated verification | Status |
|---|---|---|---|---|
| R12.1 | Secure enrollment and transport | `fleet/pki.py` (private CA, EKU-restricted certificates, token with CA fingerprint), `fleet/link.py::enroll`, mutual TLS in `fleet/hub.py` | `test_certificates_and_tokens`, `test_a_forged_hub_is_refused_before_the_secret_is_sent`, `test_mutual_tls_and_revocation` | Verified live (localhost TLS) |
| R12.2 | Fleet view + alert queue + triage | `Hub.checkin / agents / alerts / triage`, console pages, `eldoctor hub agents / alerts / triage` | `test_enroll_report_respond_and_distribute_intel`, `test_triage_rules_and_audit`, `test_cli_hub_and_agent_processes` | Verified live |
| R12.3 | Remote response, bounded by the endpoint | `Hub.create_command`, `HubLink.execute` (allow-list, safety guards, at most once, audited both sides) | kill of a real process, replay executed once, refused actions, enforce refused | Verified live |
| R12.4 | Fleet threat intel | `Hub.add_intel / intel_snapshot`, `HubLink._apply_intel` (+ fix: intel/*.csv reloaded at start) | intel applied and withdrawn; `test_analyst_added_indicators_survive_a_restart` | Verified live |
| R12.5 | Silent / tampered agents | `Hub.sweep` (HUB-001/002), `_check_audit_head` (HUB-003), revoked (HUB-004), notifications | `test_silent_agent_is_an_alert_and_its_return_too`, `test_audit_trail_rollback_on_an_endpoint_is_detected` | Verified live |
| R12.6 | Analyst web console, safe | `fleet/console.py` | `test_web_console_security` (XSS, CSRF, roles, cookies, CSP) | Verified live |
| R12.7 | Deployable hub | `eldoctor hub install-service` (unprivileged account, hardened unit), release smoke test runs a hub | `test_hub_service_install_is_hardened_and_unprivileged`, build_release smoke test | Unit verified; the systemd service itself not run here (no root) |
