# Live lab on a Wazuh server

This guide installs the lab on an **all-in-one Wazuh server** (manager, indexer and dashboard on one machine), for example the official Wazuh OVA in VirtualBox. It was tested on the **Wazuh 4.14.7 OVA** (Amazon Linux 2023, Python 3.9.25) in VirtualBox on 23 October 2026: install, `wazuh-logtest` checks for all 11 rules, and the live demo. Other 4.x versions should work, but run `wazuh/test_rules.sh` to check.

> Use a lab machine, never a production manager. Take a VM snapshot first.

## 0. Free disk space first

The Wazuh OVA has a 25 GB disk. On 23 October 2026 ours filled up to 100 % while the lab was running: Wazuh's vulnerability-detection content had grown to 13 GB in `/var/ossec/queue/vd/feed`, and a second download of 4.9 GB was sitting in `/var/ossec/queue/vd_updater/tmp`. With a full disk the manager cannot write archives or alerts and the demo shows nothing.

Check before every session (you want at least 3 GB free):

```bash
df -h /
```

The lab does not need vulnerability detection, so we turned it off on the lab VM (a backup of `ossec.conf` is kept):

```bash
sudo cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.before-vd-off
sudo sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' /var/ossec/etc/ossec.conf
sudo grep -A2 '<vulnerability-detection>' /var/ossec/etc/ossec.conf     # shows <enabled>no</enabled>
sudo sh -c 'rm -rf /var/ossec/queue/vd_updater/tmp/*'                    # half-finished download
sudo systemctl restart wazuh-manager
```

Note the `sh -c '...'`: with a plain `sudo rm -rf /var/ossec/queue/vd_updater/tmp/*`, your own shell expands the `*` before sudo runs, cannot read that root-only folder, and nothing is deleted. `wazuh/walkthrough.sh` prints a warning in step 1 if less than 3 GB is free or if vulnerability detection is on with less than 8 GB free.

## What gets changed

| Item | Change | Undo |
|---|---|---|
| `/var/ossec/etc/rules/iotsoc_rules.xml` | new rules 100600–100629 | `uninstall.sh` deletes it |
| `/var/ossec/etc/ossec.conf` | two `<localfile>` blocks between `iotsoc-lab` markers; `<logall_json>` set to `yes` if it was `no` | `uninstall.sh` removes the blocks and restores `logall_json` |
| `/var/log/iotsoc/` | `gateway.json` (IoT events) and `ml_alerts.json` (ML results) | `uninstall.sh --purge` |
| `/opt/iotsoc/` | Python virtual environment and trained model | `uninstall.sh --purge` |
| `/usr/local/bin/iotsoc` | command wrapper | `uninstall.sh` |

A timestamped copy of `ossec.conf` is saved before every change. JSON archives (`logall_json`) make Wazuh write **every** event to `/var/ossec/logs/archives/archives.json`, which the scorer reads. They use disk space, so turn them off again after the workshop (`uninstall.sh` does this).

## 1. Get the code onto the server

From a shell on the Wazuh server (the VM console, or `ssh wazuh-user@<server-ip>`), either use the one-line installer, which downloads the code to `/opt/iotsoc/src` and runs the install script:

```bash
curl -sL https://raw.githubusercontent.com/Salarsefat/iot-soc-anomaly-lab/main/wazuh/bootstrap.sh | sudo bash
```

or do it by hand:

```bash
curl -L https://github.com/Salarsefat/iot-soc-anomaly-lab/archive/refs/heads/main.tar.gz | tar xz
cd iot-soc-anomaly-lab-main
sudo bash wazuh/install.sh
```

### Guided walkthrough (for recording a video)

`wazuh/walkthrough.sh` runs the whole thing in 10 titled steps: clean start, server checks, install, what was installed, rule tests, sample events, the live demo, the alerts Wazuh recorded, one ML alert in full, and next steps. Each step starts on a clean screen and waits for Enter, so you can talk over it. A full run takes about 10 minutes. Download it to `/tmp`, not to your home folder:

```bash
cd /tmp && curl -fsSLO https://raw.githubusercontent.com/Salarsefat/iot-soc-anomaly-lab/main/wazuh/walkthrough.sh
sudo bash walkthrough.sh
```

No internet at the venue? The install (step 2) needs GitHub and PyPI, but everything after it works offline. Once the lab is installed, run the installed copy and skip the uninstall and install steps:

```bash
sudo bash /opt/iotsoc/src/wazuh/walkthrough.sh --no-install
```

## 2. What the install does

The script stops with a clear message if the rule IDs are already in use or the Wazuh configuration does not validate (it restores the backup in that case). It needs internet access to install Python packages from PyPI. At the end it trains the model, which takes about a minute, and runs `wazuh/test_rules.sh`, which should finish with:

```
OK: all IoT SOC rules fired as expected
```

## 3. Run the demo

```bash
sudo iotsoc demo
```

This replays **two simulated hours in about three minutes** (`--speed 40`). It also starts the scorer, which follows `archives.json`. In the terminal you will see:

* `[ATTACK hh:mm] <scenario> on <device> (MITRE) - signature rule … should fire` when a scripted incident begins
* `[ML HIGH  ]` / `[ML MEDIUM]` lines when the scorer sends an alert to Wazuh, with the reasons

Demo schedule (minutes after start): telnet brute force on cam-02 (10), exfiltration from cam-04 (30), *benign* camera firmware rollout (50), C2 beaconing on sens-03 (65), MQTT recon on sens-07 (80), internal scan from hvac-02 (95).

Options: `--speed 20` for a slower, 6-minute run; `--minutes 60` for a shorter stream; `--source gateway` to read the gateway log directly if archives are disabled.

## 4. See it in the Wazuh dashboard

Open the dashboard (`https://<server-ip>`), go to **Threat Hunting** (or **Discover** with the `wazuh-alerts-*` index pattern), set the time range to *Last 15 minutes*, and use these queries:

| Query | Shows |
|---|---|
| `rule.groups:iotsoc` | everything from this lab |
| `rule.groups:iotsoc_signature` | signature rules (brute force, wildcard subscription, unsigned firmware, scan) |
| `rule.groups:iot_ml` | ML alerts; open one and read `data.reasons`, `data.voters`, `data.severity` |
| `rule.id:100622` | high-severity ML alerts only |

Useful columns: `rule.id`, `rule.level`, `data.device_id`, `rule.description`, `data.reasons`. The dashboard timestamp is when Wazuh received the event. The simulated time is in `data.ts` (gateway events) and `data.window_start` (ML alerts).

Talking point: the exfiltration and the C2 beaconing produce **ML alerts only**, because no signature rule covers them. The brute force, the wildcard subscription and the scan produce **both**.

### Reference run (Wazuh 4.14.7 OVA, 23 Oct 2026, 11:42 local time)

Run through `wazuh/walkthrough.sh`. `sudo iotsoc demo` printed `scored 480 device-windows from 2404 events: 51 anomalous windows -> 16 alerts sent to Wazuh (35 repeats suppressed, 0 late events)`. Step 7 of the walkthrough counted the rule IDs written to `/var/ossec/logs/alerts/alerts.json` during the demo:

| Rule | Meaning | Alerts |
|---|---|---|
| 100601 | failed device login | 90 |
| 100602 | brute force (frequency rule) | 9 |
| 100603 | successful device login | 1 |
| 100604 | wildcard MQTT subscription | 2 |
| 100605 | signed firmware installed (benign rollout) | 4 |
| 100608 | internal scan (frequency rule) | 14 |
| 100621 | ML anomaly, medium | 9 |
| 100622 | ML anomaly, high | 7 |

Rule 100606 (unsigned firmware) does not appear because the rogue-firmware attack is not in the 2-hour demo; it is in the offline experiment.

Three of the 16 ML alerts are false alarms: sens-01, hvac-02 and sens-02, all **medium**, each an ordinary MQTT reconnect that scored 1-2 % above the threshold. Replaying the same stream offline gives the same 16 alerts at any time of day, so this is model behaviour, not a timing glitch. The alert reason shows it (`small deviations only: MQTT connections 1 (usual 0); MQTT subscriptions 1 (usual 0)`), which makes it a useful triage example. Earlier runs had 14 or 16 alerts; the exact number depends on where the 5-minute windows fall.

## 5. Run the pieces separately (optional)

```bash
sudo iotsoc live                       # terminal 1: scorer follows archives.json
sudo iotsoc replay --speed 40          # terminal 2: writes the demo stream
sudo bash wazuh/test_rules.sh          # re-check the rules with wazuh-logtest
```

## Troubleshooting

| Symptom | Check |
|---|---|
| No `[ML …]` lines | Is `logall_json` on? `sudo grep logall_json /var/ossec/etc/ossec.conf`. Is `archives.json` growing? `sudo tail -f /var/ossec/logs/archives/archives.json`. You can also try `sudo iotsoc demo --source gateway`. |
| No IoT events in the dashboard | `sudo grep iotsoc /var/ossec/logs/ossec.log` should show the two files being analysed. Gateway events are rule level 0 except logins, firmware and config changes, so most of them are only in archives, not in alerts. |
| `test_rules.sh` reports a missing rule | Paste the sample lines from `iotsoc samples` into `sudo /var/ossec/bin/wazuh-logtest` and see which phase fails. Note that frequency rules (100602, 100608) need their parent rule at level 1 or higher; with a level-0 parent the correlation never fired on 4.14.7. |
| Brute-force rule fires a little later than expected | In the logtest run, 100602 (`frequency="10"`) fired after the 11th failure. Wazuh counts frequency slightly differently from the Python rule mirror (≥ 10 per 5-minute window). |
| `pip install` fails | The server needs internet access to PyPI. Check DNS and the VM's NAT adapter. |
| `No space left on device`, or the demo shows nothing | Disk full. See section 0. |
| `curl: (23) Failure writing output` when downloading the walkthrough | You are in a folder you cannot write to, or the disk is full. Use `cd /tmp` first and check `df -h /`. |
| Alerts appear twice | The demo appends to `gateway.json`. Running it twice replays twice; that is expected. |

## Uninstall

```bash
sudo bash wazuh/uninstall.sh            # rules, config blocks, wrapper; archives back to previous state
sudo bash wazuh/uninstall.sh --purge    # also deletes /var/log/iotsoc and /opt/iotsoc
```

Alerts already indexed stay in the Wazuh indexer until your retention policy removes them.
