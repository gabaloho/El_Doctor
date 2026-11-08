"""El Doctor - host monitoring, detection and automated response (SOAR-lite).

El Doctor started as a curses system-metrics monitor.  This package turns it
into a small endpoint security tool:

* collectors   - system metrics, processes, network connections, logs
* detection    - heuristics, threat-intel IOCs, Sigma rules, YARA (optional),
                 everything mapped to MITRE ATT&CK
* playbooks    - YAML SOAR-style playbooks with monitor / interactive / enforce
                 modes and safety guards
* response     - kill, suspend, quarantine, block-ip, forensics collection
* notify       - email, Slack, Teams, Discord, webhooks (Shuffle/n8n/Tines),
                 TheHive, syslog/CEF, JSONL
* auth         - mandatory user registration with roles
* deploy       - Windows / Linux / Docker / Kubernetes / cloud VM generators
"""

__version__ = "2.1.0"        # the only place the version is written (pyproject reads it)
__all__ = ["__version__"]
