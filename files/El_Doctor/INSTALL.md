# Installing El Doctor

## The easy way: the installer for your computer

Download **one file** from the project's **Releases** page, open it, and follow the steps. Nothing else to install.

| Your computer | Download | Then |
|---|---|---|
| **Windows 10 / 11** | `ElDoctor-Setup-<version>.exe` | double-click it and follow the wizard (below) |
| **Mac** (Apple silicon) | `ElDoctor-<version>.dmg` | open it, drag **El Doctor** onto **Applications**, open El Doctor from Launchpad |
| **Ubuntu, Debian, Linux Mint** | `eldoctor_<version>_amd64.deb` | double-click it and press *Install* (or `sudo apt install ./eldoctor_<version>_amd64.deb`) |
| **Fedora, RHEL, Rocky, AlmaLinux, openSUSE** | `eldoctor-<version>-1.x86_64.rpm` | double-click it and press *Install* (or `sudo dnf install ./eldoctor-<version>-1.x86_64.rpm`) |

Then open **El Doctor** from the Start menu, Launchpad or applications menu.

### Windows setup wizard, step by step

1. **Who is it for?** Choose *Install for all users* (recommended: needs an administrator password once). Choose
   *Install for me only* if you are not an administrator: El Doctor then protects your account while it is open.
2. **Licence and folder.** Click *Next*.
3. **Options.** *Protect this computer around the clock* is ticked for all-users installations: El Doctor then
   runs in the background from start-up, for everyone, even when nobody has it open. Untick it if you only want to
   use it now and then. A desktop shortcut is optional.
4. **Who manages El Doctor?** This appears only with round-the-clock protection. Enter the person who looks after
   this computer (usually you): a user name, your name, an e-mail address, and a password (10 characters or more,
   with 3 of: lower case, upper case, digit, symbol). Reports about deleted files go to this e-mail address.
5. **Finish.** Leave *Open El Doctor now* ticked.
   * With round-the-clock protection: sign in with the user name and password from step 4.
   * Otherwise: El Doctor asks you to create your account (the first account is the administrator).

*"Windows protected your PC"?* That appears while the installer is not code-signed. Click *More info*, then
*Run anyway*. Check the download first (section 1).

**Removing it:** *Settings → Apps → El Doctor → Uninstall*. You are asked whether to also delete El Doctor's
records. The default is to keep them, and a later reinstall finds them again.

**Upgrading:** run the setup of the new version. Your accounts, settings and records are kept.

**Other people on the computer:** they open El Doctor and create their own account. They can view it; the
administrator decides who may do more (*Users & settings*).

### Mac

Open the `.dmg` and drag **El Doctor** onto **Applications**. The first time, *right-click → Open* on El Doctor if
macOS says the developer cannot be verified (the app is not notarized yet). El Doctor asks you to create your
account.

### Linux packages

The package adds El Doctor to the applications menu. To protect the whole computer around the clock, for every user
and from start-up, run this once in a terminal:

```bash
sudo eldoctor install-service          # asks who manages El Doctor (user name, e-mail, password)
```

*Remove:* uninstall the package in the software centre (`sudo apt remove eldoctor` / `sudo dnf remove eldoctor`).
This also turns the background service off; records are kept until `sudo apt purge eldoctor`.

### For IT departments: silent installation

```bat
set ELDOCTOR_ADMIN_PASSWORD=<the administrator's password>
ElDoctor-Setup-<version>.exe /VERYSILENT /ALLUSERS /TASKS="service,desktopicon" /ADMINUSER=alice /ADMINEMAIL=alice@corp.example /ADMINNAME="Alice Smith"
```

`/CURRENTUSER` (without `/TASKS=service`) installs for the current user only. The password is read from the
environment, never from the command line. Linux:
`sudo ELDOCTOR_ADMIN_USER=alice ELDOCTOR_ADMIN_EMAIL=alice@corp.example ELDOCTOR_ADMIN_PASSWORD=... eldoctor install-service --quiet`.

---

## The portable way (no installation)

El Doctor is also a **standalone executable**: download, extract, run. No Python, no `pip`, nothing to install.
This suits advanced users, servers and USB sticks. Two ways to use it:

| | Personal use | 24/7 protection (recommended for servers and shared PCs) |
|---|---|---|
| How | run the program while you need it | install it as a service that starts at boot |
| Watches | your own processes and files | every process, every user's files, firewall blocking |
| Needs | nothing | administrator / root once, to install |

## 1. Download

From the project's **Releases** page, take the file for your system:

| System | File | Runs on |
|---|---|---|
| Windows 10 / 11, Server 2016+ (64-bit) | `eldoctor-<version>-windows-x86_64.zip` | |
| Linux (64-bit) | `eldoctor-<version>-linux-x86_64.tar.gz` | glibc 2.28+: RHEL / Alma / Rocky 8+, Ubuntu 20.04+, Debian 10+, Fedora, SUSE 15+ |
| macOS (Apple silicon) | `eldoctor-<version>-macos-arm64.tar.gz` | current macOS releases |
| Anything with Python 3.9+ | `eldoctor-<version>-py3-none-any.whl` | `pipx install eldoctor-<version>-py3-none-any.whl` |

**Check the download** before running it, installers included. Put `SHA256SUMS.txt` next to the file and run:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing            # Linux
shasum -a 256 -c SHA256SUMS.txt --ignore-missing        # macOS
Get-FileHash .\ElDoctor-Setup-<version>.exe             # Windows: compare with the line in SHA256SUMS.txt
```

Every release also has build provenance you can check: `gh attestation verify <file> --repo <owner>/<repo>`.
The CycloneDX SBOM (`eldoctor-<version>-sbom.cdx.json`) lists every bundled third-party component.

## 2. Run it (personal use)

**Windows:** extract the zip and double-click **`El Doctor.exe`**. The window opens on the registration form.
If SmartScreen says "Windows protected your PC" on an unsigned build, choose *More info → Run anyway*.
`eldoctor.exe` in the same folder is the command-line version (`eldoctor.exe doctor`, `eldoctor.exe tui`, ...).
To act on other users' processes, right-click → *Run as administrator*.

**Linux:**

```bash
tar xzf eldoctor-<version>-linux-x86_64.tar.gz
cd eldoctor-<version>-linux-x86_64
./eldoctor            # terminal: registration -> login -> live console
./eldoctor gui        # or the desktop window
```

**macOS:**

```bash
tar xzf eldoctor-<version>-macos-arm64.tar.gz && cd eldoctor-<version>-macos-arm64
xattr -d com.apple.quarantine eldoctor   # unsigned builds only: otherwise Gatekeeper blocks the download
./eldoctor
```

**First start:**
1. Registration is required. The **first user becomes the administrator**.
2. You get an API key once (for automation). Keep it or ignore it.
3. Log in, and the console opens.

Check the installation at any time; it also tells you how to fix what it finds:

```bash
./eldoctor doctor
```

Your data lives in `~/.eldoctor` (Windows: `%USERPROFILE%\.eldoctor`). Set `ELDOCTOR_HOME` to use another folder.

## 3. Install as a service (24/7, whole machine)

The release archive contains the service installer next to the executable.

**Linux (systemd):**

```bash
sudo ./install.sh
```

This installs `/opt/eldoctor/bin/eldoctor`, the `eldoctor` systemd service (starts at boot, restarts on failure),
`/etc/eldoctor/config.yaml`, and the data folder `/var/lib/eldoctor` (root only). With auditd present it adds
audit rules, so the kernel names **who** ran a program or deleted a file. It also raises the inotify watch limit.
It asks you to register the administrator, unless `ELDOCTOR_UNATTENDED=1`; in that case set `ELDOCTOR_ADMIN_USER`
and `ELDOCTOR_ADMIN_EMAIL` in `/etc/eldoctor/eldoctor.env`, and the password is generated into
`/var/lib/eldoctor/admin-password`.

Afterwards, any user opens the console **without sudo**: `eldoctor login`, then `eldoctor tui` or `eldoctor gui`.
Logs: `journalctl -u eldoctor -f` and `/var/lib/eldoctor/logs/eldoctor.log`.

**Windows (Scheduled Task as SYSTEM):** open PowerShell *as Administrator* in the extracted folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -Mode Both        # Service = agent only, Desktop = shortcuts only, Both = both
```

This installs to `C:\Program Files\ElDoctor` with data in `C:\ProgramData\ElDoctor` (SYSTEM only). Desktop users
get *El Doctor* shortcuts that talk to the service. We recommend installing
[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon): it gives full process, network and file
telemetry (events 1, 3, 11, 23, 26, 15).

**Any Windows or Linux computer, from the command line** (administrator / root), is the same as the installers do:
`eldoctor install-service` (asks who manages El Doctor) and `eldoctor uninstall-service [--purge]`.

**macOS:** there is no background service yet. Run `sudo ./eldoctor run --headless` from a LaunchDaemon if you need it.

## 4. Configure e-mail (needed for data-wipe reports)

When someone deletes many files, El Doctor e-mails the **registered administrators**: who did it, and every file
and folder affected. Until an SMTP server is configured, these reports wait in the outbox; they are sent later,
nothing is lost. Edit the config (`~/.eldoctor/config.yaml`, `/etc/eldoctor/config.yaml` or
`C:\ProgramData\ElDoctor\config.yaml`):

```yaml
activity:
  report:
    smtp: {smtp_host: smtp.example.com, smtp_port: 587, starttls: true,
           username: alerts@example.com, password_env: ELDOCTOR_SMTP_PASSWORD, from: alerts@example.com}
```

Put the password in the environment, never in the file: `/etc/eldoctor/eldoctor.env` for the Linux service, or a
machine environment variable on Windows. Then restart, and check delivery:

```bash
eldoctor doctor --network                 # can the SMTP server be reached?
eldoctor activity reports --retry         # send waiting reports now (analyst / admin)
```

Alerts can also go to Slack, Teams, Discord, webhooks (Shuffle, n8n, Tines), TheHive and syslog/SIEM: see
`notifications.channels` in the config and README section 5.

## 5. Upgrade

* **Personal use:** replace the executable with the new one. Your data folder is kept and upgraded automatically.
* **Service:** extract the new release and run the installer again (`sudo ./install.sh` / `.\install.ps1`). It
  detects the existing installation and replaces the program only: users, keys, configuration and records are
  kept, and nobody is re-registered.

Check with `eldoctor --version` and `eldoctor doctor`.

## 6. Uninstall

* Personal use: delete the executable. Delete `~/.eldoctor` too if you do not want to keep the records.
* Linux service: `sudo ./uninstall.sh`. Data stays in `/var/lib/eldoctor` and config in `/etc/eldoctor`;
  delete them by hand.
* Windows service: `.\uninstall.ps1` as Administrator. Data stays in `C:\ProgramData\ElDoctor`.

## 7. Backups

Back up the **whole data folder** while the agent is stopped: the database, `keys/`, `logs/`, `evidence/` and
`quarantine/`. The database's seals need `keys/`: a database restored without its keys is reported as tampered.
Write down the *genesis signing key* printed by `eldoctor audit verify` somewhere off the machine. It proves later
that the audit trail was not rebuilt.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Anything | `eldoctor doctor` - it names the problem and the fix |
| Forgot the admin password | `sudo eldoctor recover-admin` (service), or `eldoctor recover-admin` as the same OS user (personal). Resets, unlocks and re-enables the account; recorded in the audit trail |
| Change your password | `eldoctor passwd` |
| "needs glibc ..." / `GLIBC_2.xx not found` on Linux | the system is older than RHEL 8 / Ubuntu 20.04: use the wheel with Python 3.9+ instead |
| GUI does not open on Linux | use `eldoctor tui`, or run from a desktop session (`DISPLAY` must be set) |
| Processes of other users are not visible / not acted on | run as administrator / root, or install the service |
| Data-wipe reports not arriving | section 4; `eldoctor activity reports` shows the last error |
| Where are the logs? | `<data folder>/logs/eldoctor.log`, plus `journalctl -u eldoctor` for the Linux service |

## 8b. Connecting computers to an El Doctor Hub (organisations)

If your organisation runs an El Doctor Hub (a central console, see docs/HUB.md), the hub administrator gives you a
token. On each computer, as administrator / root, run: `eldoctor enroll EDH1-...`.
Windows: the *El Doctor (command line)* shortcut, with *Run as administrator*.

## 9. From source (developers)

```bash
python -m pip install --require-hashes -r requirements.lock   # pinned, hash-checked dependencies (Python 3.11+)
python -m pip install -e .                                    # or just: python eldoctor
python -m pytest
python -m pip install -r packaging/requirements-build.txt
python packaging/build_release.py                             # tests -> standalone executable -> smoke test -> release/
```

Releases are built by `.github/workflows/release.yml` when a tag `v<version>` is pushed. It builds on Linux
(AlmaLinux 8, for glibc 2.28), Windows and macOS, smoke-tests every executable on its own system, and publishes the
executables, wheel, sdist, SBOM, checksums and provenance.
