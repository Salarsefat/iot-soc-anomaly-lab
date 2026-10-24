#!/usr/bin/env bash
# Install the IoT SOC anomaly lab on an all-in-one Wazuh server.
# Written for the Wazuh 4.x OVA (Amazon Linux 2023). Run from the repo root:
#     sudo bash wazuh/install.sh
# What it changes (all reversible with wazuh/uninstall.sh):
#   * /var/ossec/etc/rules/iotsoc_rules.xml            custom rules 100600-100629
#   * /var/ossec/etc/ossec.conf                        two <localfile> blocks (marked) and,
#                                                      if needed, <logall_json>yes</logall_json>
#   * /var/log/iotsoc/{gateway,ml_alerts}.json         input files Wazuh reads
#   * /opt/iotsoc/venv, /opt/iotsoc/bundle.joblib      Python env + trained model
#   * /usr/local/bin/iotsoc                            command wrapper
# A timestamped backup of ossec.conf is kept next to it.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OSSEC=/var/ossec
CONF="$OSSEC/etc/ossec.conf"
RULES_DST="$OSSEC/etc/rules/iotsoc_rules.xml"
LOG_DIR=/var/log/iotsoc
BASE=/opt/iotsoc
VENV="$BASE/venv"
STATE="$BASE/install-state"
MARK_BEGIN="<!-- iotsoc-lab: begin -->"
MARK_END="<!-- iotsoc-lab: end -->"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash wazuh/install.sh"
[ -x "$OSSEC/bin/wazuh-control" ] || die "no Wazuh manager found in $OSSEC"
[ -f "$REPO_DIR/iotsoc/__init__.py" ] || die "run this script from inside the iot-soc-anomaly-lab folder"
mkdir -p "$BASE"
touch "$STATE"

say "Checking that rule IDs 100600-100629 are free"
clash=$(grep -rlE 'id="1006[0-2][0-9]"' "$OSSEC/etc/rules" 2>/dev/null | grep -v 'iotsoc_rules.xml' || true)
[ -z "$clash" ] || die "rule IDs 100600-100629 already used in: $clash"

say "Backing up ossec.conf"
backup="$CONF.iotsoc-backup-$(date +%Y%m%d-%H%M%S)"
cp -p "$CONF" "$backup"
echo "    $backup"

say "Installing rules -> $RULES_DST"
install -m 660 -o wazuh -g wazuh "$REPO_DIR/wazuh/rules/iotsoc_rules.xml" "$RULES_DST"

say "Creating $LOG_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"
touch "$LOG_DIR/gateway.json" "$LOG_DIR/ml_alerts.json"
chmod 644 "$LOG_DIR/gateway.json" "$LOG_DIR/ml_alerts.json"

if grep -qF "$MARK_BEGIN" "$CONF"; then
  say "localfile blocks already present"
else
  say "Adding localfile blocks to ossec.conf"
  cat >> "$CONF" <<EOF

$MARK_BEGIN
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$LOG_DIR/gateway.json</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>$LOG_DIR/ml_alerts.json</location>
  </localfile>
</ossec_config>
$MARK_END
EOF
fi

if grep -q '<logall_json>no</logall_json>' "$CONF"; then
  say "Enabling JSON archives (<logall_json>yes</logall_json>) so the scorer sees every event"
  sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' "$CONF"
  grep -q '^logall_json_changed=1' "$STATE" || echo "logall_json_changed=1" >> "$STATE"
else
  say "JSON archives already enabled (or set elsewhere) - leaving as is"
fi

say "Validating the configuration"
if ! "$OSSEC/bin/wazuh-analysisd" -t; then
  cp -p "$backup" "$CONF"; rm -f "$RULES_DST"
  die "wazuh-analysisd -t failed; restored the previous configuration"
fi

say "Restarting wazuh-manager"
systemctl restart wazuh-manager
sleep 5
systemctl is-active --quiet wazuh-manager || die "wazuh-manager did not come back; check /var/ossec/logs/ossec.log"

say "Creating the Python environment in $VENV"
if ! python3 -m venv "$VENV" 2>/dev/null; then
  command -v dnf >/dev/null && dnf install -y -q python3-pip
  command -v apt-get >/dev/null && apt-get install -y -qq python3-venv
  python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install -q --upgrade pip
"$VENV/bin/python" -m pip install -q -r "$REPO_DIR/requirements.txt"

say "Installing the 'iotsoc' command"
cat > /usr/local/bin/iotsoc <<EOF
#!/bin/sh
# IoT SOC anomaly lab wrapper (installed by wazuh/install.sh)
export PYTHONPATH="$REPO_DIR\${PYTHONPATH:+:\$PYTHONPATH}"
cmd="\$1"
case "\$cmd" in
  live|demo) shift; exec "$VENV/bin/python" -m iotsoc "\$cmd" --bundle "$BASE/bundle.joblib" "\$@" ;;
  train)     shift; exec "$VENV/bin/python" -m iotsoc train --out "$BASE/bundle.joblib" "\$@" ;;
  *)         exec "$VENV/bin/python" -m iotsoc "\$@" ;;
esac
EOF
chmod 755 /usr/local/bin/iotsoc

say "Training the model bundle (about a minute)"
/usr/local/bin/iotsoc train

if [ -z "${IOTSOC_SKIP_TEST:-}" ]; then
  say "Testing the rules with wazuh-logtest"
  bash "$REPO_DIR/wazuh/test_rules.sh" || echo "    (rule test reported problems - see above)"
fi

say "Done"
cat <<EOF
Next:
  sudo iotsoc demo            # 2 simulated hours in ~3 minutes, alerts appear in Wazuh
Then in the Wazuh dashboard (Threat Hunting / Discover) filter on:
  rule.groups:iotsoc
Undo everything with:  sudo bash wazuh/uninstall.sh
EOF
