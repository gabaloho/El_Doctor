#!/usr/bin/env bash
# Reproducible El Doctor lab: fresh data dir, registration, mock SOAR/SIEM receivers, lab threat-intel
# feeds, agent in the requested mode, then the attack simulations.
#   scripts/lab.sh [enforce|interactive|monitor] [scenario,scenario,...]
#   PYTHON=/path/to/python3.14 scripts/lab.sh enforce      # choose the interpreter (no pip install needed)
#   LAB_SCOPE_PID=<pid> ...   response scope: only processes started (directly or not) by <pid> may be touched.
#                             Default: this script's own process tree. LAB_SCOPE_PID=none = whole host.
set -uo pipefail
MODE="${1:-enforce}"; ONLY="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ELDOCTOR_HOME="${ELDOCTOR_HOME:-/tmp/ed_lab}" ELDOCTOR_WEBHOOK_SECRET=lab-hmac-secret \
       ELDOCTOR_THEHIVE_KEY=lab-thehive-key LAB_PW='Str0ng!Passw0rd' PATH="$HOME/.local/bin:$PATH"
PY="${PYTHON:-python3}"
cd "$ROOT"
SCOPE="${LAB_SCOPE_PID:-$$}"
CFG=/tmp/ed_lab_config.yaml
"$PY" - "$ROOT/scripts/lab_config.yaml" "$CFG" "$SCOPE" <<'PYCFG'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
if sys.argv[3] != "none":
    cfg.setdefault("safety", {})["only_descendants_of"] = [int(sys.argv[3])]
yaml.safe_dump(cfg, open(sys.argv[2], "w"), sort_keys=False)
PYCFG
ED="$PY -m eldoctor --config $CFG"

[[ -f /tmp/ed_agent.pid ]] && kill "$(cat /tmp/ed_agent.pid)" 2>/dev/null
pkill -f "lab_config.yaml run" 2>/dev/null; pkill -f mock_receivers.py 2>/dev/null; sleep 2
rm -rf "$ELDOCTOR_HOME" /tmp/ed_received.jsonl /tmp/eldoctor-sim
"$PY" "$ROOT/scripts/simulate_attacks.py" prepare
nohup "$PY" "$ROOT/scripts/mock_receivers.py" --out /tmp/ed_received.jsonl --files /tmp/eldoctor-sim/feeds \
      > /tmp/ed_mock.log 2>&1 &
sleep 1
$ED register --non-interactive --username alice --email alice@acme.example --full-name "Alice Analyst" \
    --org "Acme SOC" --use-case soc --deploy-target linux --password-env LAB_PW | grep Registered
$ED login --username alice --password-env LAB_PW
$ED intel update
nohup $ED run --headless --mode "$MODE" --syslog-port 5514 --log-file /tmp/eldoctor-sim/auth.log \
      > /tmp/ed_agent.log 2>&1 &
echo $! > /tmp/ed_agent.pid
sleep 4; $PY --version; head -4 /tmp/ed_agent.log
if [[ "$MODE" == "monitor" ]]; then EXP=alive; else EXP=killed; fi
[[ "$ONLY" == "none" ]] && exit 0
"$PY" "$ROOT/scripts/simulate_attacks.py" run --expect "$EXP" ${ONLY:+--only "$ONLY"}
