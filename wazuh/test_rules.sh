#!/usr/bin/env bash
# Feed sample events through wazuh-logtest and check which IoT rules fire.
#   sudo bash wazuh/test_rules.sh
set -uo pipefail
LOGTEST=/var/ossec/bin/wazuh-logtest
[ -x "$LOGTEST" ] || { echo "wazuh-logtest not found"; exit 1; }

gw='"iotsoc":"gateway","device_type":"camera","device_ip":"10.20.2.12"'
lines=()
for i in $(seq 1 12); do
  lines+=("{\"ts\":\"2026-09-19T02:10:0${i: -1}.000Z\",$gw,\"kind\":\"device_auth\",\"device_id\":\"cam-02\",\"service\":\"telnet\",\"outcome\":\"failure\",\"account\":\"admin\",\"src_ip\":\"203.0.113.21\"}")
done
lines+=("{\"ts\":\"2026-09-19T02:38:00.000Z\",$gw,\"kind\":\"device_auth\",\"device_id\":\"cam-02\",\"service\":\"telnet\",\"outcome\":\"success\",\"account\":\"root\",\"src_ip\":\"203.0.113.21\"}")
lines+=("{\"ts\":\"2026-09-19T11:23:00.000Z\",\"iotsoc\":\"gateway\",\"device_type\":\"sensor\",\"device_ip\":\"10.20.1.17\",\"kind\":\"mqtt_subscribe\",\"device_id\":\"sens-07\",\"topic\":\"#\"}")
lines+=("{\"ts\":\"2026-09-19T03:30:00.000Z\",\"iotsoc\":\"gateway\",\"device_type\":\"lock\",\"device_ip\":\"10.20.3.12\",\"kind\":\"fw_update\",\"device_id\":\"lock-02\",\"fw_version\":\"9.9.9-x\",\"fw_source\":\"203.0.113.99\",\"fw_signed\":\"false\",\"bytes_in\":4000000}")
lines+=("{\"ts\":\"2026-09-19T14:01:00.000Z\",$gw,\"kind\":\"fw_update\",\"device_id\":\"cam-01\",\"fw_version\":\"4.2.1\",\"fw_source\":\"fw.camvendor.example\",\"fw_signed\":\"true\",\"bytes_in\":50000000}")
for i in $(seq 10 33); do
  lines+=("{\"ts\":\"2026-09-19T20:15:${i}.000Z\",\"iotsoc\":\"gateway\",\"device_type\":\"hvac\",\"device_ip\":\"10.20.4.12\",\"kind\":\"flow\",\"device_id\":\"hvac-02\",\"dst_ip\":\"10.20.3.$i\",\"dst_port\":502,\"proto\":\"tcp\",\"dst_zone\":\"internal\",\"allowlisted\":\"no\",\"bytes_out\":80,\"bytes_in\":0}")
done
lines+=("{\"ts\":\"2026-09-19T10:05:00.000Z\",\"iotsoc\":\"gateway\",\"device_type\":\"hvac\",\"device_ip\":\"10.20.4.11\",\"kind\":\"config_change\",\"device_id\":\"hvac-01\",\"account\":\"facility-admin\",\"setting\":\"setpoint\"}")
lines+=("{\"iotsoc\":\"ml\",\"detector\":\"autoencoder+vote\",\"model_version\":\"test\",\"device_id\":\"cam-04\",\"device_type\":\"camera\",\"window_start\":\"2026-09-19T15:15:00Z\",\"window_end\":\"2026-09-19T15:20:00Z\",\"severity\":\"high\",\"votes\":3,\"voters\":\"iforest,lof,autoencoder\",\"score\":2.4,\"signature_overlap\":\"none\",\"reasons\":\"bytes sent to the internet 29.9 MB (usual 0 B-39.5 kB)\"}")
lines+=("{\"iotsoc\":\"ml\",\"detector\":\"autoencoder+vote\",\"model_version\":\"test\",\"device_id\":\"hvac-03\",\"device_type\":\"hvac\",\"window_start\":\"2026-09-19T09:40:00Z\",\"window_end\":\"2026-09-19T09:45:00Z\",\"severity\":\"medium\",\"votes\":1,\"voters\":\"autoencoder\",\"score\":0.8,\"signature_overlap\":\"none\",\"reasons\":\"failed logins in the last hour 14 (usual 0)\"}")

out=$(printf '%s\n' "${lines[@]}" | "$LOGTEST" 2>&1)
fired=$(printf '%s\n' "$out" | grep -oE "id: '1006[0-9]{2}'" | grep -oE '1006[0-9]{2}' | sort | uniq -c)
echo "Rules fired (count x rule id):"
echo "$fired"
status=0
for id in 100601 100602 100603 100604 100605 100606 100607 100608 100609 100621 100622; do
  if ! printf '%s\n' "$fired" | grep -q " $id\$"; then
    echo "MISSING: rule $id did not fire"; status=1
  fi
done
if [ $status -eq 0 ]; then echo "OK: all IoT SOC rules fired as expected"; else
  echo "--- last part of wazuh-logtest output ---"; printf '%s\n' "$out" | tail -40; fi
exit $status
