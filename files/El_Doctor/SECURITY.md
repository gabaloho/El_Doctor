# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**, through the repository's *Security → Report a vulnerability* form
(GitHub private advisories), not in public issues. Include the version (`eldoctor --version`), the platform and
steps to reproduce. You will get an answer within 7 days. Fixes are released as a new patch version, with an
advisory.

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | yes |
| < 2.1 | no - upgrade (section 5 of INSTALL.md, data is kept) |

## Verifying what you run

* Every release publishes `SHA256SUMS.txt`, a CycloneDX SBOM and GitHub build provenance. See INSTALL.md §1.
* Release builds install dependencies from `requirements.lock` with `--require-hashes`.
* The executables are unsigned unless the release notes say otherwise. Signing is wired into the build
  (`ELDOCTOR_SIGN_CMD`) and needs the project's certificates.

## Hardening checklist for production

1. **Run the service** (`install.sh` / `install.ps1`), not a personal instance. Then the data folder is root /
   SYSTEM only, and every console is an authenticated client of the agent.
2. **Forward the audit trail off the host**: set `audit.forward` (syslog TLS / webhook) to your SIEM. Record the
   genesis key printed by `eldoctor audit verify` off-host, or pin it in `audit.genesis_fingerprint`.
3. **Configure SMTP** for the registered admins (data-wipe reports) and a notification channel for alerts.
   Keep secrets in environment variables (`*_env` keys), never in `config.yaml`.
4. **Restrict who may use the API**: `api.allowed_os_groups`, `api.admin_os_groups` (e.g. `[sudo, wheel]`).
5. **Telemetry**: auditd with the bundled rules (Linux), Sysmon (Windows).
6. **Start in `interactive` mode.** Review what El Doctor would do before you switch to `enforce`, then add
   allow-lists for the tools of your environment.
7. Keep at least 1 GB free for the data folder. Back it up with its `keys/` (INSTALL.md §7).
8. Review `eldoctor doctor` after every change.

## Threat model in one paragraph

The agent is the only trust anchor. Consoles never touch its data, and every permission is checked inside the
agent. Approvals, roles, blocks and quarantine records are sealed. The audit trail is a hash chain signed with
forward-secure one-time keys, so stealing the keys today cannot rewrite yesterday. The user-activity record is
sealed into the same chain. Residual risks: an attacker who already controls the host as root / SYSTEM *while the
agent runs* can act as the agent from then on (not retroactively), and can stop it. That stop is recorded as a
monitoring gap at the next start, and the SIEM copy stays intact. Details: README §6b and
`docs/PRODUCTION_READINESS.md`.
