#!/usr/bin/env bash
# Undo wazuh/install.sh.   sudo bash wazuh/uninstall.sh [--purge]
#   --purge also deletes /var/log/iotsoc and /opt/iotsoc (venv + model).
set -euo pipefail
OSSEC=/var/ossec
CONF="$OSSEC/etc/ossec.conf"
BASE=/opt/iotsoc
STATE="$BASE/install-state"

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
cp -p "$CONF" "$CONF.iotsoc-uninstall-backup-$(date +%Y%m%d-%H%M%S)"

rm -f "$OSSEC/etc/rules/iotsoc_rules.xml"
sed -i '/<!-- iotsoc-lab: begin -->/,/<!-- iotsoc-lab: end -->/d' "$CONF"
if [ -f "$STATE" ] && grep -q '^logall_json_changed=1' "$STATE"; then
  sed -i 's|<logall_json>yes</logall_json>|<logall_json>no</logall_json>|' "$CONF"
  sed -i '/^logall_json_changed=1/d' "$STATE"
  echo "JSON archives disabled again (they were off before install)."
fi
rm -f /usr/local/bin/iotsoc

"$OSSEC/bin/wazuh-analysisd" -t
systemctl restart wazuh-manager

if [ "${1:-}" = "--purge" ]; then
  rm -rf /var/log/iotsoc "$BASE"
  echo "Removed /var/log/iotsoc and $BASE."
fi
echo "IoT SOC lab removed. Alerts already indexed stay in Wazuh until they age out."
