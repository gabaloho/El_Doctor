"""MITRE ATT&CK (Enterprise) technique catalogue used by El Doctor rules.

Only the techniques El Doctor can actually detect are listed; unknown IDs are
still accepted and rendered with a link so Sigma rules bringing their own
tags keep working.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# technique id -> (name, tactic(s))
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.004": ("Masquerading: Masquerade Task or Service", "Defense Evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence, Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1059.006": ("Command and Scripting Interpreter: Python", "Execution"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1078": ("Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "Defense Evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    "T1222.002": ("File and Directory Permissions Modification: Linux and Mac", "Defense Evasion"),
    "T1485": ("Data Destruction", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1561.001": ("Disk Wipe: Disk Content Wipe", "Impact"),
    "T1561.002": ("Disk Wipe: Disk Structure Wipe", "Impact"),
    "T1565.001": ("Data Manipulation: Stored Data Manipulation", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence, Privilege Escalation"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence, Privilege Escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation, Defense Evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1588.001": ("Obtain Capabilities: Malware", "Resource Development"),
}


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def describe(ids: List[str]) -> List[Dict[str, str]]:
    out = []
    for tid in ids or []:
        tid = tid.upper()
        name, tactic = TECHNIQUES.get(tid, ("(see ATT&CK)", ""))
        out.append({"id": tid, "name": name, "tactic": tactic, "url": technique_url(tid)})
    return out


def from_sigma_tags(tags: List[str]) -> List[str]:
    """Convert Sigma tags (attack.t1059.004) into technique IDs (T1059.004)."""
    out = []
    for t in tags or []:
        t = str(t).lower()
        if t.startswith("attack.t") and t[8:9].isdigit():
            out.append(t[len("attack."):].upper())
    return out


def matches(technique_ids: List[str], selectors: List[str]) -> bool:
    """True if any technique equals or is a sub-technique of any selector."""
    for tid in technique_ids or []:
        for sel in selectors or []:
            sel = sel.upper()
            if tid.upper() == sel or tid.upper().startswith(sel + "."):
                return True
    return False
