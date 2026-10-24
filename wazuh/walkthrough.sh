#!/usr/bin/env bash
# Guided, step-by-step install + demo of the IoT SOC lab on a Wazuh server.
# Made for screen recordings: every step clears the screen, prints a title and a
# short explanation, runs, and waits for Enter. Start it from /tmp (it needs no
# space in your home folder):
#   cd /tmp && curl -fsSLO https://raw.githubusercontent.com/Salarsefat/iot-soc-anomaly-lab/main/wazuh/walkthrough.sh
#   sudo bash walkthrough.sh
# No internet (e.g. at a workshop venue)? If the lab is already installed, run the
# installed copy and skip the uninstall/install steps:
#   sudo bash /opt/iotsoc/src/wazuh/walkthrough.sh --no-install
# NONINTERACTIVE=1 runs all steps without pausing or clearing the screen.
set -u
NO_INSTALL=""
[ "${1:-}" = "--no-install" ] && NO_INSTALL=1
REPO="${IOTSOC_REPO:-Salarsefat/iot-soc-anomaly-lab}"
ALERTS=/var/ossec/logs/alerts/alerts.json

B=$'\033[1m'; C=$'\033[1;36m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; R=$'\033[0m'

title() {   # title "STEP n" "Short name"
  if [ -z "${NONINTERACTIVE:-}" ]; then clear 2>/dev/null || printf '\033[H\033[2J'; else echo; fi
  echo "${C}==============================================================${R}"
  echo "${C}  $1: $2${R}"
  echo "${C}==============================================================${R}"
}
say() { echo "  $*"; }
run() { echo "${Y}\$ $*${R}"; eval "$@"; }
pause() {
  [ -n "${NONINTERACTIVE:-}" ] && return 0
  echo
  read -r -p "${G}>> Press Enter for the next step${R} " _ </dev/tty
}

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo bash walkthrough.sh"; exit 1; }
if [ -n "$NO_INSTALL" ] && { [ ! -x /usr/local/bin/iotsoc ] || [ ! -f /opt/iotsoc/bundle.joblib ]; }; then
  echo "The lab is not installed yet, so --no-install cannot be used."
  echo "Run once without it (needs internet): sudo bash walkthrough.sh"
  exit 1
fi

title "IoT SOC LAB" "Wazuh rules + ML anomaly detection, from zero"
say "Code:  https://github.com/$REPO"
say "Wazuh: $(/var/ossec/bin/wazuh-control info 2>/dev/null | grep -o 'v[0-9.]*' | head -1)   Host: $(hostname)"
say ""
say "0 start clean           5 what the IoT gateway sends"
say "1 check the server      6 live demo: attacks + ML alerts"
say "2 install (one line)    7 what Wazuh recorded"
say "3 what was installed    8 one ML alert, as Wazuh stores it"
say "4 test the rules        9 dashboard, snapshot, uninstall"
pause

title "STEP 0" "Start clean"
say "If the lab was installed before, remove it first: rules, log"
say "inputs, Python env and model. Wazuh itself is not touched."
if [ -n "$NO_INSTALL" ]; then
  say "Skipped (--no-install): we keep the lab that is already installed."
elif [ -x /opt/iotsoc/src/wazuh/uninstall.sh ]; then
  run "bash /opt/iotsoc/src/wazuh/uninstall.sh --purge"
else
  say "Nothing installed yet - nothing to remove."
fi
pause

title "STEP 1" "Check the server"
say "We need root, Python 3, internet access (GitHub + PyPI), free disk."
run "head -2 /etc/os-release"
run "python3 -V"
run "df -h / | tail -1"
avail_kb=$(df -Pk / | awk 'NR==2 {print $4}')
if [ "${avail_kb:-0}" -lt 3000000 ]; then
  echo "${Y}  WARNING: less than 3 GB free. Free space before the demo (see docs/live-wazuh.md).${R}"
fi
vd=$(sed -n '/<vulnerability-detection>/,/<\/vulnerability-detection>/p' /var/ossec/etc/ossec.conf \
     | grep -o '<enabled>[a-z]*' | head -1 | cut -d'>' -f2)
say "Vulnerability detection: ${vd:-not configured}"
if [ "${vd:-}" = "yes" ] && [ "${avail_kb:-0}" -lt 8000000 ]; then
  echo "${Y}  WARNING: its feed download needs several GB; turn it off or free space (docs/live-wazuh.md).${R}"
fi
[ -n "$NO_INSTALL" ] && say "(internet is only needed for the install in step 2, skipped today)"
run "curl -s -m 5 -o /dev/null -w 'github.com: HTTP %{http_code}\n' https://github.com"
run "curl -s -m 5 -o /dev/null -w 'pypi.org:   HTTP %{http_code}\n' https://pypi.org/simple/pip/"
pause

title "STEP 2" "Download and install (one line)"
say "bootstrap.sh downloads the code to /opt/iotsoc/src, then install.sh:"
say " 1 backs up ossec.conf      5 restarts the Wazuh manager"
say " 2 adds rules 100600-100629  6 creates a Python environment"
say " 3 adds 2 JSON log inputs    7 trains the anomaly models"
say " 4 turns on JSON archives      (about 2 minutes in total)"
if [ -n "$NO_INSTALL" ]; then
  say "Skipped (--no-install). It was installed earlier with this one line:"
  echo "${Y}\$ curl -sL https://raw.githubusercontent.com/$REPO/main/wazuh/bootstrap.sh | sudo bash${R}"
else
  run "curl -sL https://raw.githubusercontent.com/$REPO/main/wazuh/bootstrap.sh | IOTSOC_SKIP_TEST=1 bash"
fi
pause

title "STEP 3" "What was installed"
say "The rules file, the two inputs Wazuh now reads, archives on,"
say "the log files and the trained model bundle."
run "grep -c '<rule id' /var/ossec/etc/rules/iotsoc_rules.xml"
run "sed -n '/iotsoc-lab: begin/,/iotsoc-lab: end/p' /var/ossec/etc/ossec.conf"
run "grep logall_json /var/ossec/etc/ossec.conf"
run "ls -l /var/log/iotsoc /opt/iotsoc/bundle.joblib"
pause

title "STEP 4" "Test the rules with wazuh-logtest"
say "Sample events go through Wazuh's own rule engine."
say "Every rule must fire at least once (count x rule id):"
run "bash /opt/iotsoc/src/wazuh/test_rules.sh | grep -E 'MISSING|OK:| 1006[0-9]{2}\$'"
pause

title "STEP 5" "What the IoT gateway sends"
say "One JSON line per event: MQTT, flows, DNS, logins, firmware."
say "Wazuh decodes these with its JSON decoder. A few examples:"
run "/usr/local/bin/iotsoc samples | head -4"
pause

title "STEP 6" "Live demo: attacks + ML alerts"
say "2 simulated hours of the building in about 3 minutes."
say "${B}[ATTACK]/[BENIGN]${R}   a scripted event starts (the ground truth)"
say "${B}[ML HIGH]/[ML MEDIUM]${R} the scorer sent an alert to Wazuh"
say "Rule alerts (brute force, wildcard MQTT, scan) come from Wazuh itself."
START_LINE=$(wc -l < "$ALERTS" 2>/dev/null || echo 0)
pause
run "/usr/local/bin/iotsoc demo"
pause

title "STEP 7" "What Wazuh recorded during the demo"
say "100601 failed login      100604 wildcard MQTT    100608 internal scan"
say "100602 brute force       100605 signed firmware  100621 ML medium"
say "100603 successful login  100606 unsigned fw *    100622 ML high"
say "(* not part of the 2-hour demo; covered by the offline experiment)"
run "tail -n +$((START_LINE + 1)) $ALERTS | grep -oE '\"id\":\"1006[0-9]+\"' | sort | uniq -c"
pause

title "STEP 8" "One ML alert, as Wazuh stores it"
say "The exfiltration from cam-04: no signature rule covers it, the models do."
say "The reasons field tells the analyst why the window is unusual."
tail -n +$((START_LINE + 1)) "$ALERTS" | grep '"iot_ml"' | python3 -c '
import json, sys
alerts = [json.loads(line) for line in sys.stdin if line.strip()]
def pick(a):
    d = a.get("data", {})
    return (d.get("device_id") == "cam-04" and d.get("severity") == "high",
            d.get("severity") == "high")
if not alerts:
    print("  (no ML alert found - did the demo run in step 6?)")
    sys.exit(0)
best = max(alerts, key=pick)
d = best.get("data", {})
for k, v in [("rule.id", best["rule"]["id"]), ("rule.level", best["rule"]["level"]),
             ("device", d.get("device_id")), ("severity", d.get("severity")),
             ("models agreeing", d.get("voters")), ("window", d.get("window_start")),
             ("reasons", d.get("reasons"))]:
    print("  %-16s %s" % (k, v))'
pause

IP=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^10\.0\.2\.' | grep -v '^$' | head -1)
title "STEP 9" "Dashboard, snapshot, uninstall"
say "Dashboard: https://${IP:-<server-ip>}  -> Threat Hunting"
say "           query  rule.groups:iotsoc   time: Last 15 minutes"
say "Snapshot:  VirtualBox -> Machine -> Take Snapshot"
say "Run again: sudo iotsoc demo"
say "Remove:    sudo bash /opt/iotsoc/src/wazuh/uninstall.sh --purge"
echo
echo "${G}Done. Code and docs: https://github.com/$REPO${R}"
