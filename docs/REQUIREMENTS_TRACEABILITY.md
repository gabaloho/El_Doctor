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
