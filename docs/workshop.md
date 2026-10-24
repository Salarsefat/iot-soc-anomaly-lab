# Workshop plan: "What do your Wazuh rules miss on an IoT network?"

Audience: SOC analysts and detection engineers who know Wazuh or another SIEM. No ML background needed.
Duration: 90 minutes (a 60-minute cut is given at the end).
You need: this repository, Python 3.9+, and optionally the live Wazuh lab ([live-wazuh.md](live-wazuh.md)).

## Learning goals

By the end, participants can:

1. Explain why signature rules and behavioural baselines catch *different* attacks on IoT devices.
2. Read an ML alert ("failed logins in the last hour 15 (usual 0)") and decide what to check next.
3. Judge an anomaly detector by *attacks found* **and** *false incidents per day*, not by accuracy.
4. Recognise benign change (firmware rollouts, broker restarts) that looks like an attack.
5. Name the limits of a synthetic evaluation before trusting its numbers.

## Agenda

| Time | Block | What happens |
|---|---|---|
| 0–10 | The problem | IoT devices cannot run agents; the gateway sees MQTT, flows, DNS and logins. Rules need a known pattern. |
| 10–25 | Live demo (video or live) | `sudo iotsoc demo`: attacks start, Wazuh rules fire for 4 of them, ML alerts with reasons appear for the rest. |
| 25–40 | How the ML part works | 5-minute windows → per-device baseline → 3 models → calibrated thresholds → severity. Show one alert and its features. |
| 40–65 | Hands-on (pairs) | Exercises 1–4 below on laptops (offline mode, no Wazuh needed). |
| 65–80 | Results discussion | Table from `output/report.html`: rules vs Isolation Forest vs autoencoder vs hybrid. Benign events. Alert budget. |
| 80–90 | Take-aways and the repo link | What you would deploy, what you would not, where to go next. |

60-minute cut: drop exercise 4 and shorten "How the ML part works" to 8 minutes.

## Before the session (presenter)

- [ ] Run `python -m iotsoc run --seeds 5` once and keep `output/report.html` open in a tab.
- [ ] If showing Wazuh live: install with `wazuh/install.sh` the day before, run `sudo iotsoc demo` once, and take a VM snapshot.
- [ ] Have the recorded demo video ready as a fallback in case the live system fails.
- [ ] Put the repository link and a QR code on the last slide.

## Exercises

All exercises use the offline mode: `python -m iotsoc run --out output`.

### 1. Read three alerts (10 min)
Open `output/ml_alerts.json`. Pick one alert on `cam-04`, one on `sens-03` and one on `hvac-03`.
For each: what does the `reasons` field claim? Which raw events would you pull from the gateway log to confirm it?
Then check `output/incidents.csv`: was it a real attack?

### 2. Where do the rules stop? (10 min)
In `output/results.md`, look at the "minutes to first alert" table.
Which attacks have no signature rule? Write a Wazuh rule (in `wazuh/rules/iotsoc_rules.xml` style) that would catch *one* of them, e.g. any internet connection from a sensor to a destination outside its vendor range.
What would that rule cost in false alarms when the vendor adds a new CDN address?

### 3. Move the threshold (10 min)
Run again with a stricter and a looser alert budget:
```bash
python -m iotsoc run --target-fpr 0.0005 --out out_strict
python -m iotsoc run --target-fpr 0.01   --out out_loose
```
Compare attacks found and false incidents per day. Which setting would you accept for 20 devices? For 2,000?

### 4. Benign change (10 min)
The firmware rollout (14:00 on the test day) is flagged on every camera.
Propose two ways to stop this without hiding a real rogue-firmware attack (hint: the `fw_signed` field, change windows, grouping alerts across a fleet).

## Discussion prompts

- The autoencoder was chosen as the main model *after* seeing these results. Why is that a problem, and how would you choose fairly?
- The simulator and the detectors were written by the same person. What bias does that create?
- Is a model alert without a clear reason actionable in your SOC?
- What happens to a 24-hour "never-seen destination" feature when a device was offline for two days?
- Which of these signals would you rather get from the vendor (signed-firmware status, allowlists) than learn with ML?

## Key messages for the close

1. Rules for what you know, baselines for what you don't. You need both.
2. Count the cost in **analyst incidents per day**, not accuracy.
3. Severity (do the models agree?) and plain-language reasons make ML alerts usable.
4. Benign change is the main source of noise; plan for it with context, not with a bigger model.
5. Synthetic labs teach the workflow; only your own telemetry can show whether it works.
