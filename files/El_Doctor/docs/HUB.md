# El Doctor Hub: one console for the whole fleet

Without a hub, every El Doctor is an island. A security team with 50 or 500 computers would have to sign in to each
one to see its alerts. If an attacker killed the agent or wiped the machine, nobody would notice until someone
looked.

**El Doctor Hub** is a central server, built into the same program (`eldoctor hub`). Every El Doctor agent reports
to it, and analysts work from one web console:

| | |
|---|---|
| **Fleet view** | Every computer: online / late / silent / revoked, last check-in, version, response mode, who is logged in, open alerts |
| **Alert queue** | Alerts from every agent in one queue. Triage: acknowledge → investigating → closed, with an assignee, a verdict (true positive, false positive, benign, duplicate) and notes |
| **Remote response** | Kill / suspend / resume / collect forensics / quarantine a process, block / unblock an IP, change the response mode, on any computer. It runs at the agent's next check-in (seconds). |
| **Fleet threat intel** | An indicator (IP, domain, hash, file name) added once is detected and blocked by every agent |
| **Silent agents** | **HUB-001** when an agent stops reporting (killed, host down or cut off, wiped), **HUB-002** when it comes back, with the length of the gap |
| **Tamper detection** | **HUB-003** (critical) when an agent's tamper-evident audit trail goes backwards or changes: its database was restored or rewritten |
| **Revocation** | A lost or compromised computer's certificate is refused from then on. **HUB-004** if it still tries to connect |
| **Notifications** | Hub alerts go to e-mail, Slack, Teams, syslog / SIEM..., with the same channel configuration as an agent |

## Set it up (Linux server, 3 commands)

```bash
sudo eldoctor hub install-service --name hub.corp.example      # or an IP; repeat --name for more
```

This creates the `eldoctor-hub` system account (the hub needs no root). It creates the hub's own certificate
authority and the hub certificate, and asks for the first hub administrator. It then starts a hardened systemd
service (read-only system, no capabilities).

* Agent API: `https://hub.corp.example:8443`. Open this port to your computers.
* Web console: `https://127.0.0.1:8444`, on the hub server itself. See *Console access* below.

Without systemd, or for a test: `eldoctor hub init --name <address>`, then `eldoctor hub serve`.

## Connect computers

1. **Create an enrollment token**: web console → *Enroll agents*, or
   `sudo -u eldoctor-hub ELDOCTOR_HUB_HOME=/var/lib/eldoctor-hub eldoctor hub token --uses 50 --note "finance"`.
   A token can serve several computers (`--uses`) and expires (24 h by default).
2. **On each computer**, as administrator / root:

   ```bash
   eldoctor enroll EDH1-eyJ1Ijoi...
   ```

   Windows: *El Doctor (command line)* shortcut → right-click → *Run as administrator*.

The running El Doctor connects within a minute; no restart is needed. `eldoctor doctor` shows the link.

For mass deployment, run the same command from your software-distribution tool (Intune, GPO, Ansible...) with one
multi-use token.

## Analysts

* **Accounts**: `eldoctor hub user-add alice --email alice@corp.example --role analyst`
  (`viewer`: read only; `analyst`: triage, respond, threat intel; `admin`: also tokens, revocation, audit,
  enforce mode).
* **Console**: sign in at `https://<console address>/`. The pages are *Fleet overview*, *Agents*, *Alerts*,
  *Commands*, *Threat intel*, *Enroll agents* (admin) and *Audit* (admin).
* **Command line on the hub**: `eldoctor hub agents | alerts | triage | respond | commands | intel | revoke | status`.

Every analyst action is recorded in the hub's forward-secure signed audit trail (*Audit* page,
`eldoctor audit verify` with `ELDOCTOR_HOME=<hub folder>`). Remote commands are also recorded on the endpoint, as
`hub:<analyst>`.

### Console access

The console listens on `127.0.0.1` by default. Choose one:

* an SSH tunnel: `ssh -L 8444:127.0.0.1:8444 hub.corp.example`, then open `https://127.0.0.1:8444`;
* a reverse proxy with your company certificate (nginx, Caddy, Traefik) in front of `127.0.0.1:8444`;
* `hub.console_listen: 0.0.0.0:8444` in `hub.yaml`, inside a management network only.

Browsers warn about the hub's own CA. Either import `pki/ca.crt` from the hub folder, or use the reverse proxy.

## Configuration (`hub.yaml` in the hub folder)

```yaml
hub:
  agent_listen: 0.0.0.0:8443
  console_listen: 127.0.0.1:8444
  public_url: https://hub.corp.example:8443   # what goes into enrollment tokens
  names: [hub.corp.example]                   # names in the hub certificate
  checkin_interval: 15       # seconds between agent check-ins
  silent_after: 180          # seconds without a check-in -> HUB-001
  token_hours: 24
  command_ttl_minutes: 60    # a command not picked up by then expires
notifications:               # same format as an agent's config.yaml
  min_severity: high
  channels:
    - {type: jsonl, path: hub-alerts.jsonl}
    - {type: email, smtp_host: smtp.corp.example, username: soc@corp.example, password_env: HUB_SMTP_PASSWORD,
       to: [soc@corp.example]}
```

**On each agent** (`config.yaml`), the endpoint decides what the hub may do there:

```yaml
hub:
  allow_commands: [ping, forensics, suspend, resume, kill, kill_tree, quarantine, block_ip, unblock_ip, set_mode]
  allow_remote_enforce: false    # the hub may not switch this computer to automatic (enforce) mode
```

## Security model

* **Mutual TLS** with the hub's private CA. Agents pin it, and the hub accepts only certificates it issued to an
  enrolled, non-revoked agent. Certificate purposes are enforced, so an agent's certificate cannot pose as the hub.
* **Enrollment** needs no trust on first use. The token carries the CA fingerprint, so an intercepted connection
  is refused *before* the secret is sent. Tokens are single-use or limited-use, expire, and are stored hashed.
* **Private keys never travel**: each agent creates its own key and sends a certificate request, and the hub
  decides the agent's identity.
* **The hub never connects to endpoints.** Agents poll, so nothing new listens on the computers, and it works
  through NAT.
* **Remote response is bounded by the endpoint.** The agent's allow-list and its safety guards apply (protected
  processes, PID-reuse check, circuit breaker). Each command runs once. Every command is recorded on both sides.
* **Web console**: no JavaScript, every value escaped (agent-reported names are attacker-controlled), a CSRF
  token on every form, HttpOnly + Secure + SameSite=Strict sessions, a strict CSP and no framing. Roles are re-read
  on every request.
* **A compromised hub is powerful.** It can send response commands to every agent within their allow-lists. Protect
  it like a domain controller: a dedicated server, a console behind a VPN or proxy, few admins. Restrict risky actions
  per host with `hub.allow_commands`.

## Backups

Back up the whole hub folder (default `/var/lib/eldoctor-hub`). It holds `pki/ca.key`: **losing it means re-enrolling
every agent, and leaking it lets someone issue agent certificates.** Keep backups encrypted.

## Limits (this version)

* The hub is a single server (SQLite). Sized for hundreds of agents. For thousands, run several hubs or put a
  database server behind it (roadmap).
* Agent certificates are valid for 825 days. Renewal is re-enrollment for now (`eldoctor enroll` with a new token).
* No policy / rule distribution yet (Sigma rules and playbooks remain per host); threat intel is distributed.
* The web console and the agent API were tested on Linux. The Windows hub was not run.
