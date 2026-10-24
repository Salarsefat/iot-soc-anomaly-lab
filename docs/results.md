# Results (seed 7, target false-alarm rate 0.002)

| detector | precision | recall | f1 | pr_auc | attacks_detected | median_minutes_to_detect | incidents_per_day | false_incidents_per_day |
|---|---|---|---|---|---|---|---|---|
| Signature rules (Wazuh-style) | 1.000 | 0.083 | 0.154 | – | 4 | 5.000 | 4.000 | 0.000 |
| Isolation Forest, raw features | 0.320 | 0.061 | 0.102 | 0.153 | 4 | 22.500 | 21.000 | 10.000 |
| Isolation Forest + device baselines | 0.273 | 0.023 | 0.042 | 0.205 | 2 | 32.500 | 11.000 | 5.000 |
| LOF + device baselines | 0.567 | 0.129 | 0.210 | 0.560 | 5 | 10.000 | 23.000 | 2.000 |
| Autoencoder + device baselines | 0.607 | 0.879 | 0.718 | 0.615 | 7 | 5.000 | 45.000 | 9.000 |
| Ensemble (2 of 3 agree) | 0.621 | 0.136 | 0.224 | 0.625 | 5 | 10.000 | 22.000 | 0.000 |
| Hybrid: rules OR ML policy | 0.607 | 0.879 | 0.718 | 0.648 | 7 | 5.000 | 45.000 | 9.000 |

## Minutes to first alert per attack

| scenario | rules | iforest_raw | iforest | lof | autoencoder | ensemble | hybrid |
|---|---|---|---|---|---|---|---|
| c2_beaconing | missed | 50 min | missed | 50 min | 5 min | 50 min | 5 min |
| exfiltration | missed | 10 min | 20 min | 10 min | 5 min | 10 min | 5 min |
| lateral_scan | 5 min | 10 min | missed | 10 min | 5 min | 10 min | 5 min |
| lowslow_bruteforce | missed | missed | missed | missed | 10 min | missed | 10 min |
| mqtt_recon | 5 min | missed | missed | missed | 5 min | missed | 5 min |
| rogue_firmware | 5 min | missed | missed | 5 min | 5 min | 5 min | 5 min |
| telnet_bruteforce | 5 min | 35 min | 45 min | 35 min | 5 min | 35 min | 5 min |

## Benign-but-unusual events flagged (devices)

| scenario | rules | iforest_raw | iforest | lof | autoencoder | ensemble | hybrid |
|---|---|---|---|---|---|---|---|
| broker_restart | 0 | 0 | 0 | 2 | 20 | 2 | 20 |
| firmware_rollout | 0 | 3 | 1 | 4 | 4 | 4 | 4 |
| maintenance | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Hybrid alerts by severity

| severity | alert_windows | attack_windows | benign_event_windows | false_incidents_per_day |
|---|---|---|---|---|
| high | 38 | 27 | 6 | 0.0 |
| medium | 153 | 89 | 20 | 9.0 |
| rule only | 0 | 0 | 0 | – |

## Across 5 seeds: mean ± std (min–max)

| detector | precision | recall | pr_auc | attacks_detected | false_incidents_per_day |
|---|---|---|---|---|---|
| rules | 1.00 ± 0.00 (1.00–1.00) | 0.08 ± 0.00 (0.08–0.08) | – | 4.00 ± 0.00 (4.00–4.00) | 0.00 ± 0.00 (0.00–0.00) |
| iforest_raw | 0.30 ± 0.03 (0.24–0.32) | 0.06 ± 0.01 (0.05–0.08) | 0.15 ± 0.02 (0.12–0.16) | 4.20 ± 0.45 (4.00–5.00) | 10.00 ± 4.24 (4.00–14.00) |
| iforest | 0.23 ± 0.07 (0.14–0.33) | 0.05 ± 0.02 (0.02–0.08) | 0.20 ± 0.02 (0.18–0.22) | 3.20 ± 0.84 (2.00–4.00) | 12.20 ± 6.91 (5.00–20.00) |
| lof | 0.52 ± 0.18 (0.20–0.63) | 0.30 ± 0.22 (0.04–0.56) | 0.51 ± 0.06 (0.45–0.58) | 4.80 ± 0.45 (4.00–5.00) | 10.60 ± 5.73 (2.00–18.00) |
| autoencoder | 0.59 ± 0.02 (0.55–0.61) | 0.93 ± 0.03 (0.88–0.96) | 0.63 ± 0.02 (0.60–0.66) | 7.00 ± 0.00 (7.00–7.00) | 10.60 ± 4.16 (6.00–15.00) |
| ensemble | 0.62 ± 0.11 (0.42–0.70) | 0.33 ± 0.21 (0.08–0.56) | 0.63 ± 0.01 (0.62–0.64) | 5.00 ± 0.00 (5.00–5.00) | 1.20 ± 2.17 (0.00–5.00) |
| hybrid | 0.59 ± 0.02 (0.55–0.61) | 0.93 ± 0.03 (0.88–0.96) | 0.66 ± 0.02 (0.65–0.69) | 7.00 ± 0.00 (7.00–7.00) | 10.60 ± 4.16 (6.00–15.00) |
