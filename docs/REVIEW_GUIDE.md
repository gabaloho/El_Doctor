# Reviewer guide: agent-side trust boundary (turns 7 and 8)

This guide tells a reviewer **what was asked, what to look for, which files to read and which
commands to run** to confirm the work is complete. Everything below runs offline on Linux with an
unprivileged account.

---

## 1. What was asked

**Turn 7: move the trust boundary into the agent (production-readiness finding P0-1)**

| # | Request | Where it lives |
|---|---|---|
| 7.1 | A local **authenticated API** | `eldoctor/api/` |
| 7.2 | **OS-level peer credentials** | `eldoctor/api/peercred.py`, `transport.py`, `winpipe.py` |
| 7.3 | **Session tokens / JWT** for stateless authentication | `eldoctor/auth/tokens.py` |
| 7.4 | CLI, GUI and TUI become **clients**; **all checks move into the agent** (RBAC for approval and admin) | `eldoctor/api/server.py` (`METHODS`, `AgentService.require`), `cli.py`, `ui/tui.py`, `ui/gui.py` |
| 7.5 | **Lock the database folder** to the service account | `eldoctor/lockdown.py`, `cli.py:cmd_service`, systemd unit / installers in `deploy/generator.py` |
| 7.6 | **Tamper-evident audit log with hash-chained records** | `eldoctor/integrity.py`, `eldoctor/storage.py` (`audit`, `verify_audit`) |
| 7.7 | **Forward audit logs to the SIEM in real time** | `eldoctor/siem.py` |
| 7.8 | The agent must **stop trusting the database**: forged approvals and audit trails must fail | `storage.py:verify_approval`, `playbooks/engine.py:process_approvals` |

**Turn 8: close the two limits documented after turn 7**

| # | Limit | Fix |
|---|---|---|
| 8.1 | "Anyone who can read the agent's key can forge seals" | **Forward-secure, publicly verifiable Ed25519 signatures** on every audit record. Each record has a one-time key, commits to the next public key (`next_pub`), and the used key is destroyed after the commit. A **genesis fingerprint** can be pinned. |
| 8.2 | "Alerts and the actions log are not sealed" | A **signed ledger**: every write to alerts, actions, users, IP blocks, quarantine records and approval requests records the row's digest in the signed chain. The agent checks rows against it before acting, and `audit verify` checks every row. |
| 8.3 | Reviewer guidance | this file |

---

## 2. Commands to run (with expected results)

```bash
cd El_Doctor
python3 -m pip install -r requirements.txt pytest pyte     # psutil, PyYAML, cryptography (+ test tools)
```

| # | Command | Expected | Time |
|---|---|---|---|
| C1 | `python3 -m pytest -q` | **204 passed** (the 14 GUI tests skip if there is no Tk or `DISPLAY`; the pty test skips without `pyte`) | ~5 min |
| C2 | `python3 -m pytest -q tests/test_api.py tests/test_integrity.py tests/test_forward_secure.py` | **59 passed**: the tests written for turns 7–8 | ~1 min |
| C3 | `python3 scripts/verify_requirements.py` | **29 passed, 0 failed**; R7.1–R7.7 and R8.1–R8.3 are the new checks | ~4 min |
| C4 | `python3 scripts/verify_requirements.py --full` | **31 passed**: adds the full pytest suite (T.1) and the 15-attack lab (T.2) | ~12 min |
| C5 | `LAB_SCOPE_PID=$$ scripts/lab.sh interactive none && ELDOCTOR_HOME=/tmp/ed_lab python3 scripts/tamper_demo.py` | every step `[PASS]`, `== result: ALL PASS` (15 checks) | ~1 min |
| C6 | `LAB_SCOPE_PID=$$ scripts/lab.sh interactive none && ELDOCTOR_HOME=/tmp/ed_lab python3 scripts/interactive_demo.py` | hog killed after `approvals approve`; miner resumed after `approvals deny` | ~1 min |
| C7 | `scripts/lab.sh enforce` | `15/15 scenarios passed` (no regression in detection or response) | ~3 min |

After C5–C7, stop the lab: `kill $(cat /tmp/ed_agent.pid); pkill -f scripts/mock_receivers.py`.

Reference outputs from the sandbox are in `docs/verification-report-full.txt`,
`docs/lab-results-enforce.txt` and `docs/lab-scorecard.json`.

> **Safety.** The lab and the demos act on real processes. `lab.sh` limits responses to its own process
> tree by default (`LAB_SCOPE_PID`). `LAB_SCOPE_PID=$$` scopes them to your shell. Do not run
> `LAB_SCOPE_PID=none scripts/lab.sh enforce` on a machine running other work: enforce mode may kill
> anything that looks malicious (for example, memfd-based tool runners).

### Manual walk-through (10 minutes, personal data folder)

```bash
export ELDOCTOR_HOME=/tmp/rev ELDOCTOR_CLIENT_DIR=/tmp/rev-client P='Str0ng!Passw0rd'
ED="python3 -m eldoctor"
$ED alerts; echo $?                                   # 2: registration required (decided by the agent)
$ED register --non-interactive --username alice --email a@x.io --password-env P
$ED login --username alice --password-env P           # JWT stored in /tmp/rev-client/sessions/, 0600
$ED run --headless --mode monitor --duration 300 &    # agent + API on /tmp/rev/api.sock
sleep 5; $ED whoami                                   # "OS identity seen by the agent: ... via unix"
ls -l /tmp/rev/api.sock /tmp/rev/keys/audit-chain/    # socket 0600; exactly ONE signing key (the next one)
$ED audit                                             # who did what, with OS user / front end per record
$ED audit verify                                      # OK ... N forward-secure Ed25519 signatures ... genesis
$ED audit verify-export /tmp/rev/audit.jsonl          # the forwarded copy verifies with public info only
ELDOCTOR_CLIENT_DIR=/tmp/rev-bob $ED register --non-interactive --username bob --email b@x.io --password-env P
ELDOCTOR_CLIENT_DIR=/tmp/rev-bob $ED login --username bob --password-env P
ELDOCTOR_CLIENT_DIR=/tmp/rev-bob $ED audit; echo $?   # 3: viewer refused by the agent, logged as api_denied
python3 -c "import sqlite3; sqlite3.connect('/tmp/rev/eldoctor.db').execute(
  \"UPDATE users SET role='admin' WHERE username='bob'\").connection.commit()"   # bob edits the DB
ELDOCTOR_CLIENT_DIR=/tmp/rev-bob $ED audit; echo $?   # 2: bob's session refused - account record tampered
$ED audit verify; echo $?                             # TAMPERED ... user 2: row was modified ...; exit 4
$ED alerts | grep ED-INT-001                          # the critical "integrity violation" incident (integrity: ok)
kill %1
```

To see the service deployment model (lockdown, service identity):
`python3 -m eldoctor service --bootstrap --duration 5` with
`ELDOCTOR_ADMIN_USER=owner ELDOCTOR_ADMIN_EMAIL=o@x.io` set. Afterwards, `stat -c '%a %n' $ELDOCTOR_HOME
$ELDOCTOR_HOME/*` shows 700 for the folder and 600 for the files.

---

## 3. What to look for (checklist)

Each item names where to read and how it is proven. Tick it when the code matches the claim.

### Turn 7

- [ ] **Front ends never open the database.**
  - `grep -n "from eldoctor.storage import\|Store(\|UserManager(\|decide_approval(" eldoctor/cli.py eldoctor/ui/*.py`
    returns nothing. Verifier R7.3 performs the same check.
  - The only in-process hosting is `AgentService` (the agent itself), used when this OS account owns
    the data folder: `api/client.py:connect`.
- [ ] **One RBAC decision point.**
  - `api/server.py`: the `@api(name, perm)` table and `AgentService.handle` → `authenticate` → `require`.
  - Every method declares its permission (`test_every_method_declares_its_permission`).
  - Every role is refused exactly where `PERMISSIONS` says
    (`test_agent_refuses_every_call_the_role_does_not_allow[viewer|analyst|admin]`).
- [ ] **Peer credentials are kernel-sourced and fail closed.**
  - `api/peercred.py:from_unix_socket` (`SO_PEERCRED` / `LOCAL_PEERCRED`).
  - `transport.py:UnixApiServer._serve` returns immediately if credentials can't be read.
  - Client-side server check: `UnixTransport.connect` with `trusted_server_uids`.
  - Per-account connection cap: `test_one_account_cannot_exhaust_the_api_connections`.
- [ ] **Tokens.**
  - `auth/tokens.py`: HS256 only (`alg=none` and other algorithms are rejected), plus `aud`/`iss`/`exp`/`nbf`.
  - `AgentService.authenticate`:
    - `ouid` must equal the peer uid, otherwise `token_peer_mismatch` is audited;
    - the `jti` denylist handles logout;
    - `token_version` handles role changes and disabled accounts;
    - the role comes from the user record, never from the token.
  - Tests: `test_token_is_a_signed_jwt_bound_to_the_os_account`, `test_forged_expired_and_alg_none_tokens_are_refused`,
    `test_role_change_disable_and_logout_revoke_tokens`.
- [ ] **Manual response can't be steered by the client.** `respond.process` takes only `pid` and
  `create_time`; the agent resolves the process and checks PID reuse
  (`test_manual_response_resolves_the_process_itself`).
- [ ] **Approvals are verified at execution time.**
  - `storage.py:verify_approval` checks the request seal, request ledger entry, decision seal, decision
    time, matching chained `approval_decided` record, the approver *currently* allowed to approve, and
    no replay.
  - `playbooks/engine.py:process_approvals` calls it and rejects with an ED-INT-001 incident.
  - Tests: `test_p0_1_forged_approval_is_refused_and_raised` (the original finding, verbatim),
    `test_approver_demoted_before_execution_is_refused`, `test_genuine_approval_executes_once_and_replay_is_refused`.
- [ ] **Lockdown.**
  - `lockdown.py`: refuses symlinks and foreign owners, 0700/0600 recursively, umask 0077; Windows
    uses `icacls` SYSTEM-only.
  - Proven by `test_lockdown_restricts_the_data_folder` and `test_cli_is_a_client_of_the_running_service`
    (modes after a real `eldoctor service` start).
- [ ] **Hash chain and truncation.**
  - `storage.py:audit`: the sealed head pointer is updated in the same transaction. A tail or head
    mismatch at append time keeps numbering after the head, so the hole stays visible.
  - `test_truncation_stays_visible_after_the_agent_writes_again`.
- [ ] **SIEM forwarding.**
  - `siem.py:AuditForwarder`: woken on every commit, per-destination cursors persisted, back-off.
  - Formats: `as_cef`, `as_rfc5424`, `as_json`.
  - Tests: `test_audit_forwarded_to_siem_in_real_time_and_verifiable` (real TCP and UDP listeners) and
    `test_forwarding_survives_an_outage_without_losing_records`.

### Turn 8

- [ ] **Forward security.**
  - `integrity.py:SigningChain`: keys are stored as `keys/audit-chain/<pub>.key`, created with
    O_EXCL + fsync, destroyed by overwriting and unlinking.
  - `storage.py:audit`:
    - it signs with the key named by the previous record's `next_pub` and creates the next one;
    - it destroys the used key **after commit**;
    - cleanup runs only in the outermost transaction, so a rollback never loses the key the
      committed tail expects.
  - Tests:
    - only one key on disk, the next one: `test_every_record_is_signed_and_used_keys_are_destroyed`;
    - an attacker holding the master key *and* the current signing key who rewrites a record is
      detected: `test_stolen_keys_cannot_rewrite_history`;
    - keeping the committed public key without its private half fails the signature:
      `test_keeping_the_committed_key_without_its_private_half_fails_the_signature`.
- [ ] **Whole-chain rebuild.** The genesis fingerprint changes and the pin catches it
  (`test_rebuilding_the_whole_chain_changes_the_genesis`, `audit.genesis_fingerprint`).
- [ ] **Public verifiability.**
  - `siem.py:verify_export` needs no secret: hash, signatures, key continuity, optional genesis pin.
  - `test_siem_copy_is_verifiable_without_any_secret`; CLI `audit verify-export`.
- [ ] **Ledger.**
  - `storage.py`: `_ledger_write` is called from `add_alert`, `add_action`, `_reseal_user`,
    `add_block`, `deactivate_block`, `add_quarantine`, `mark_restored` and `create_approval`. The digest
    is computed from the row *read back from the DB* inside the same transaction.
  - `ledger_state` is used by `user_row_ok`, `active_blocks`, `quarantine_record`, `verify_approval`
    and `decide_approval`. `verify_ledger` is part of `verify_audit`.
- [ ] **Trust decisions use verified data.**
  - `enable_verified_ledger` (called for the service/headless/embedded roles in `AgentService.__init__`)
    builds the index from a full verification and refreshes it incrementally.
  - A record that is not signed by the committed key is **never** trusted
    (`test_key_holder_cannot_rewrite_the_ledger_record_either`).
  - The one-shot CLI uses a per-record fast path (`_record_trusted`): hash, MAC, signature, continuity
    with the previous record, and linkage.
- [ ] **HMAC-key holders can't forge state.**
  `test_hmac_key_holder_cannot_promote_a_user`, `test_blocks_quarantine_and_approval_requests_need_the_ledger`.
- [ ] **Alerts and actions.**
  - `test_alerts_and_actions_are_tamper_evident` covers an edited alert, a deleted alert, a rewritten
    action status and a planted row.
  - The API and CLI show per-row integrity (`test_api_and_cli_show_row_integrity`); the GUI alert
    detail shows "record verified / WARNING".
- [ ] **Upgrades.**
  - A pre-chain DB is adopted once (`test_pre_integrity_database_is_adopted_once`).
  - A turn-7 DB (v1 records, no ledger) is upgraded under a new signed chain
    (`test_database_from_the_first_chain_version_is_upgraded`).
  - Rows whose HMAC seal is already broken are *not* adopted into the ledger.
- [ ] **Tests can fail.** Mutation checks were run in the sandbox: with signature verification
  disabled, or the ledger always returning "ok", the corresponding tests fail. To repeat, monkeypatch
  `eldoctor.integrity.verify_signature` to return `True`, or `Store.ledger_state` to return `"ok"`,
  and run `tests/test_forward_secure.py`.

---

## 4. Files to check

**New**

| File | What it is |
|---|---|
| `eldoctor/api/server.py` | `AgentService`: request pipeline, RBAC table, every API method, lifecycle (listener, agent, integrity monitor) |
| `eldoctor/api/client.py` | `connect()` (socket first, in-process hosting only on a folder you own), `ApiClient`, per-user token storage, `RemoteAgent` (what the TUI/GUI display) |
| `eldoctor/api/transport.py` | JSON-lines framing, `UnixApiServer` (peer creds, admission, per-account cap), `UnixTransport` (server verification), `InProcessTransport` |
| `eldoctor/api/peercred.py` | kernel peer credentials (Linux / macOS / BSD) |
| `eldoctor/api/winpipe.py` | Windows named-pipe server/client (DACL, first-instance flag, client PID → token SID, pipe-owner check) – **not executed here** |
| `eldoctor/auth/tokens.py` | stateless JWT (HS256) |
| `eldoctor/integrity.py` | keyring, HMAC seals, chain hash v1/v2, Ed25519 forward-secure `SigningChain`, `verify_records`, row digests, fingerprints |
| `eldoctor/siem.py` | real-time audit forwarder (syslog UDP/TCP/TLS, webhook, JSONL), CEF/RFC 5424/JSON, `verify_export` |
| `eldoctor/lockdown.py` | data-folder lockdown |
| `tests/test_api.py`, `tests/test_integrity.py`, `tests/test_forward_secure.py` | turns 7–8 tests |
| `scripts/tamper_demo.py` | live replay of the original attack and of the key-holder attacks |
| `docs/REVIEW_GUIDE.md` | this file |

**Modified** (main points)

| File | Change |
|---|---|
| `eldoctor/storage.py` | explicit transactions; migrations; sealed rows; signed, chained `audit()` with truncation resistance and forward-secure keys; ledger; `verify_approval`; `verify_audit` / `verify_ledger` |
| `eldoctor/auth/users.py` | sealed + ledgered user rows, `token_version`, last-admin / emptied-table guards, `can_approve`; session files removed |
| `eldoctor/playbooks/engine.py` | `process_approvals` verifies before acting |
| `eldoctor/agent.py` | approver check wired in; ED-INT-001 integrity incidents |
| `eldoctor/response/actions.py` | restore only sealed + ledgered records whose vault copy still matches its SHA-256 |
| `eldoctor/cli.py` | every command is an API call; `service` locks the folder and serves the API; `audit verify / verify-export / --all`; exit codes 2 and 3 |
| `eldoctor/ui/tui.py`, `eldoctor/ui/gui.py` | clients of `RemoteAgent` / the API; attach to a running service; per-row integrity in the GUI alert view |
| `eldoctor/config.py`, `data/default_config.yaml` | `client_dir()`, `api_endpoint()`, `api:` and `audit:` sections (forwarding, genesis pin) |
| `eldoctor/deploy/generator.py` | systemd `RuntimeDirectory` + socket env + `StateDirectory` 0700; Windows ACL / non-elevated shortcuts; container client dir; audit-forward templates |
| `eldoctor/ui/runtime.py`, `_bootstrap.py`, `requirements.txt`, `pyproject.toml` | new dependency `cryptography`; existing GUI runtimes are upgraded in place |
| `scripts/lab.sh`, `interactive_demo.py`, `verify_requirements.py` | lab response scope by default; checks R7.x / R8.x |
| `README.md` §6b, `docs/PRODUCTION_READINESS.md` P0-1, `docs/REQUIREMENTS_TRACEABILITY.md` turns 7–8 | documentation |

---

## 5. Threat model: what each attacker achieves now

| Attacker | Before turn 7 | After turns 7–8 |
|---|---|---|
| Viewer using the CLI/GUI/API | blocked by front-end checks only | refused by the agent (exit 3), logged as `api_denied`, forwarded to the SIEM |
| Local user copying another user's token file | n/a (session files) | refused: token bound to the OS uid; `token_peer_mismatch` audited |
| Local non-admin editing `eldoctor.db` | forged approval executed; audit rewritten | cannot open the folder (service lockdown); if they could, every forgery is refused or detected (ED-INT-001) |
| Holder of the HMAC master key (reads the data folder) | – | recomputed seals are not enough: the signed ledger disagrees; history cannot be re-signed |
| Holder of **every** key file (root / service account, offline copy) | – | cannot alter or re-sign any existing record (the key is destroyed). Rebuilding the chain changes the genesis fingerprint; the SIEM copy is unchanged. |
| Root **while the agent runs** | everything | can append new records with the current one-time key (= act as the agent), as they can kill processes without El Doctor. Can't rewrite history; appended records are forwarded in real time. |

---

## 6. Known limits and what was not verified here

* **Windows**: the named-pipe transport, pipe-owner verification and SYSTEM-only ACL lockdown are
  written and reviewed but have **never run** (no Windows in the sandbox; P0-2). Also not run: macOS
  `LOCAL_PEERCRED`.
* **Single OS account**: the sandbox had one unprivileged user and no root. Cross-account behaviour
  (another user's token, unknown peers, groups, admin OS groups) is tested by passing peer identities
  to the same `handle()` the socket server calls. A root service with a `0666` socket and non-root
  clients was not run.
* **SIEM products**: delivery was tested against local TCP/UDP/TLS listeners and a mocked webhook,
  not against Splunk, Elastic or Wazuh themselves. UDP syslog cannot confirm delivery; use TCP or TLS.
* **Forensic remnants**: used keys are overwritten and unlinked, but copy-on-write or SSD storage may
  retain old blocks. Use full-disk encryption.
* **Performance**: about 4 ms per audit append (key generation, signature, two fsyncs, DB commit).
  Full verification costs about 0.2 ms per record (roughly 2 s per 10k records) at agent start and
  every `audit.verify_interval_minutes`.

## 7. Design choices worth challenging in review

1. **Service socket 0666 by default.** Authentication is per request, by token plus kernel peer
   credentials. Tighten with `api.socket_group` (0660) or `api.allowed_os_groups`.
2. **Self-registration stays on by default** (as before: new accounts are viewers). Disable with
   `registration.self_service: false`. The *first* (admin) account can only be created from the
   agent's own OS account or root.
3. **In-process hosting** on a data folder the current account owns (personal install). It goes
   through the same `handle()`; it is impossible on a locked service folder, and never used when a
   system service is installed.
4. **HS256 for session tokens** (symmetric). Only the agent issues and verifies them, so there is no
   reason for public keys. Audit signatures are asymmetric because *others* must verify them.
5. **At-least-once forwarding.** Duplicates are possible after crashes (carry `seq` + `hash`, so they
   de-duplicate easily); loss is not possible except over UDP.
6. **Fail closed on integrity breaks.** A record that breaks key continuity is never trusted for
   decisions. After a genuine key loss this affects one record, and the loss itself is raised as a
   critical incident.

## 8. Behaviour changes users will notice

* After upgrading, everyone logs in once more (sessions moved from DB files to agent-signed tokens in
  the user's client folder). Existing databases are sealed and recorded in the ledger automatically
  on first start.
* `eldoctor audit` hides ledger bookkeeping records (`--all` shows them). `alerts` and `actions` show
  an integrity column.
* Non-admins see only their own user record. `config show` shows the agent's config (admin);
  `--local` shows the local file.
* New dependency: `cryptography`.
* Windows shortcuts are no longer elevated when the service is installed.
* `scripts/lab.sh` scopes responses to its own process tree by default.
