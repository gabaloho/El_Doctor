"""Firewall backends for block_ip.

* linux  : iptables / ip6tables (fallback nftables) - needs root / CAP_NET_ADMIN
* windows: netsh advfirewall - needs Administrator
* other / unprivileged: "app-level" enforcement - the IP goes into El Doctor's
  block list, any process that connects to it raises ED-NET-003 and the
  'blocked-connection' playbook kills it.  Honest reporting: the result tells
  you which backend was actually used.
"""
from __future__ import annotations

import ipaddress
import subprocess
from typing import List, Tuple

from eldoctor.config import IS_LINUX, IS_WINDOWS, is_privileged, system_tool

COMMENT = "eldoctor"


def _run(cmd: List[str]) -> Tuple[bool, str]:
    tool = system_tool(cmd[0])
    if not tool:
        return False, f"{cmd[0]} not found in trusted system directories"
    cmd = [tool] + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def backend_name() -> str:
    if not is_privileged():
        return "app-level"
    if IS_LINUX and (system_tool("iptables") or system_tool("nft")):
        return "iptables" if system_tool("iptables") else "nftables"
    if IS_WINDOWS and system_tool("netsh"):
        return "windows-firewall"
    return "app-level"


def commands_for(ip: str, backend: str, remove: bool = False) -> List[List[str]]:
    v6 = ipaddress.ip_address(ip).version == 6
    if backend == "iptables":
        tool = "ip6tables" if v6 else "iptables"
        op = "-D" if remove else "-I"
        return [[tool, op, "INPUT", "-s", ip, "-m", "comment", "--comment", COMMENT, "-j", "DROP"],
                [tool, op, "OUTPUT", "-d", ip, "-m", "comment", "--comment", COMMENT, "-j", "DROP"]]
    if backend == "nftables":
        fam = "ip6" if v6 else "ip"
        if remove:
            return [["nft", "delete", "element", "inet", "eldoctor", f"blocked{'6' if v6 else '4'}", "{", ip, "}"]]
        return [["nft", "add", "table", "inet", "eldoctor"],
                ["nft", "add", "set", "inet", "eldoctor", "blocked4", "{", "type", "ipv4_addr;", "}"],
                ["nft", "add", "set", "inet", "eldoctor", "blocked6", "{", "type", "ipv6_addr;", "}"],
                ["nft", "add", "chain", "inet", "eldoctor", "out", "{", "type", "filter", "hook", "output",
                 "priority", "0;", "}"],
                ["nft", "add", "chain", "inet", "eldoctor", "in", "{", "type", "filter", "hook", "input",
                 "priority", "0;", "}"],
                ["nft", "add", "rule", "inet", "eldoctor", "out", fam, "daddr", f"@blocked{'6' if v6 else '4'}", "drop"],
                ["nft", "add", "rule", "inet", "eldoctor", "in", fam, "saddr", f"@blocked{'6' if v6 else '4'}", "drop"],
                ["nft", "add", "element", "inet", "eldoctor", f"blocked{'6' if v6 else '4'}", "{", ip, "}"]]
    if backend == "windows-firewall":
        name = f"ElDoctor block {ip}"
        if remove:
            return [["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]]
        return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=block",
                 f"remoteip={ip}"],
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out", "action=block",
                 f"remoteip={ip}"]]
    return []


def apply(ip: str, remove: bool = False) -> Tuple[str, bool, str]:
    """Returns (backend, ok, message)."""
    backend = backend_name()
    cmds = commands_for(ip, backend, remove)
    if not cmds:
        return "app-level", True, ("no privileged firewall available - enforced by El Doctor "
                                   "(connections to this IP are detected and their processes killed)")
    errors = []
    for cmd in cmds:
        ok, msg = _run(cmd)
        # nft 'add table/set/chain/rule' may already exist - ignore those errors
        if not ok and not (backend == "nftables" and cmd[2] in ("table", "set", "chain", "rule")):
            errors.append(f"{' '.join(cmd)}: {msg}")
    if errors:
        return backend, False, "; ".join(errors)
    return backend, True, f"{'removed from' if remove else 'added to'} {backend}"
