# Phase 8: Existing Data Assessment and Diversity Gap Report

**Inputs (read-only):** `outputs/supervised_soc_dataset.parquet`, `outputs/merged_soc_dataset.parquet`, `outputs/merged_soc_dataset_balanced.parquet`, and the Phase 2–7 reports.
**Reproduce:** `python scripts/assess_phase8.py` writes `outputs/phase8/phase8_existing_data_assessment.json`. Every number below comes from that file. The script checks the SHA-256 of every protected dataset before and after running, and it confirmed that **nothing was modified**.

## 1. Headline numbers

| Measure | Value |
| :--- | :--- |
| Benign labelled rows | 19,956 |
| Unique benign rows (Phase 7 key: 10 content fields) | **4,260** |
| Unique benign `raw_log` strings (non-null) | 2,211 |
| Benign rows with **no `raw_log`** (network-flow records only) | 3,126 (2,049 unique flow tuples) |
| Distinct benign **templates** (variable tokens masked) | **435** |
| Suspicious labelled rows | 44 |
| Unique suspicious rows / unique `raw_log` | 44 / 44 |
| Distinct suspicious **templates** | **1** |
| Independent suspicious sources (hosts × templates) | **2** |
| Malicious rows | 0 |
| Unlabelled rows | 100,000 (all from the **synthetic** Dataset 1) |

> **The 44 suspicious rows are not 44 independent attack patterns.** They are one device-status message, emitted by two hosts as a running counter.

## 2. Suspicious rows in detail

**The template.** All 44 rows reduce to this:
```
<PRI><TS> local<N>: Host: <HOST> Duration: <N>:<N>:<N> Count: <N>; INFORMATIONAL: Authentication failure.
```

| Dimension | Distribution |
| :--- | :--- |
| Host | HOST-0002: 23, HOST-0006: 21 |
| `event_type` | auth_failure: 44 |
| `source` | generic_log: 44 |
| `severity` | informational: 44 |
| Attack category | **None recorded by the source.** `auth_failure` is an event type, not an ATT&CK category. |
| `user`, `source_ip`, `dest_ip`, ports, `protocol` | Null in all 44 rows |
| Time span | 2024-07-26 11:10:29 → 11:21:00 UTC (10.5 minutes) |
| Trailing NUL byte (`\x00`) | 44 / 44 |

**Counter analysis:**
- **HOST-0002:** the `Count` field runs 903,030 → 903,053. That is 24 consecutive values, of which 23 are present.
- **HOST-0006:** it runs 903,289 → 903,310. That is 22 consecutive values, of which 21 are present.
- **Duration:** about 6,836 hours on both hosts, rising about 30 s per row.

These rows are therefore successive emissions of **two continuously incrementing status counters**. A counter of about 900k over about 6,836 hours is consistent with a long-standing condition repeating roughly every 27 seconds. It does not look like 44 separate attack attempts.

The WitFoo labels are engine output (Tier C, see the mapping plan). Nothing in the data shows whether this condition is malicious or a misconfiguration.

**A near-duplicate of the same family is labelled benign:**

| Label | Syslog PRI | Host | Message | Rows |
| :--- | :--- | :--- | :--- | :--- |
| 1 | 142 (local1.info) | HOST-0002 | `INFORMATIONAL: Authentication failure.` | 23 |
| 1 | 142 | HOST-0006 | `INFORMATIONAL: Authentication failure.` | 21 |
| 0 | 141 (local1.notice) | HOST-0002 | `NOTICE: Scheduled job failed. (deviceInfo)` | 2 |
| 0 | 141 | HOST-0006 | `NOTICE: Scheduled job failed. (deviceInfo)` | 2 |

Within this family, the label is perfectly predicted by the PRI value `<142>` versus `<141>`, and by the words INFORMATIONAL versus NOTICE. That is a shortcut a model can learn without learning anything about security.

## 3. Data quality problems

| # | Problem | Evidence | Impact |
| :--- | :--- | :--- | :--- |
| Q1 | **Single positive template** | 1 template, 2 hosts | The model learns this one string, not "authentication attack" |
| Q2 | **Label shortcuts** | `event_type == auth_failure` is 100% class 1; `source == generic_log` is 100% class 1 apart from 5 benign rows; HOST-0002/0006 are 44 of the 48 rows on those hosts; PRI `<142>` versus `<141>` | Leakage if these fields reach the prompt |
| Q3 | **The fine-tuning notebook would drop every positive** | `training/SIEM_Qwen3_4B_finetune.ipynb` cell 6 removes rows whose model features (`dest_port, method, url, status_code, bytes, user, auth_method, user_agent`) are all empty. In our schema, 44/44 suspicious and 16,081/19,956 benign rows have all of these null. Six of the features do not exist in our schema, and `source` is not aliased to `log_source`. *(Derived from reading the notebook code; the notebook was not run.)* | Training would see 0 positives. The notebook's input features need redesigning before any fine-tuning. |
| Q4 | **47% of the Phase 7 benign sample has no log text** | 205 of 440 benign rows in `merged_soc_dataset_balanced` are `communication` flows with null `raw_log` | The model sees almost nothing for these rows |
| Q5 | **Heavy benign repetition** | 19,956 rows → 4,260 unique → 435 templates. HOST-0001 accounts for 14,156 rows. Top templates are crond, systemd-logind and filebeat | Benign variety is much lower than the row count suggests |
| Q6 | **`timestamp` is ingest time, not event time** | All 20,000 rows fall in 2024-07-26 11:10–11:21, while syslog headers inside `raw_log` show Jan (11,913), Dec (2,243) and Jul (1,522) | Time-based splitting and analysis on `timestamp` would mislead |
| Q7 | **Security-relevant events are labelled benign** | 1 Cisco Stealthwatch "Suspect Long Flow" CEF notification; 2 Symantec "Intrusion prevention submission" events; 52 `critical`-severity Symantec rows; 1,011 benign rows / 69 templates contain words like failed, unauthorized or blocked (mostly filebeat, integration and Cisco errors) | Not mislabels by definition (WitFoo benign means no rule matched), but the model will see alert-like text with label 0. These are possible hard negatives; we do not relabel them. |
| Q8 | **Dataset 1 is synthetic** | The HF card says synthetic; timestamps run 2020-07-12 → 2030-07-10; CEF strings contain verdict phrases such as "Possible golden ticket usage" | The 100,000 "additional unlabelled events" are not genuine events and should not be labelled |
| Q9 | **Original raw inputs are not in the repository** | `dataset/dataset1.txt` and `dataset/dataset2.txt` are 0 bytes; Phase 2 read `/tmp/soc_merged_sample.parquet`, which is not preserved | The 120k master is the earliest artefact we have; provenance back to the WitFoo release version cannot be checked yet |
| Q10 | **WitFoo token version unknown** | The v2.1.0 card says v2 tokens do not correspond to v1 tokens | Cross-version dedup must use record UUIDs (`artifact_id`), not tokenised text |
| Q11 | **Trailing NUL bytes** | 44/44 suspicious rows, plus the 4 benign device-status rows | Another class-correlated token; keep it in `raw_log`, but normalise it in the model input |

**Already sound:** no duplicate `event_id`s, and no identical `raw_log` or template carrying both labels in the supervised set.

## 4. Missing attack categories

Coverage of the categories you asked for. *Existing* means the current 20,000 labelled rows. *Candidates* lists only sources whose documentation names the category.

| Category | Existing | Candidate sources (from the source research) |
| :--- | :--- | :--- |
| Authentication attacks / brute force | Weak: 1 engine-flagged status template, no user or IP | AIT-LDS/ADS (password cracking), CIC-IDS2017 (FTP/SSH-Patator), TON_IoT (password), LANL (red-team auth); WitFoo to be profiled |
| Privilege escalation | **None** | AIT-LDS V2, AIT-ADS; UWF (too sparse); OTRF/EVTX (no per-event labels) |
| Network intrusion / scanning | **None** | AIT (nmap, dirb, WPScan), CIC-IDS2017, UNSW-NB15, UWF-ZeekData22, TON_IoT |
| SQL injection | **None** | CSIC 2010, ECML/PKDD 2007; CIC-IDS2017 (flows only) |
| XSS | **None** | ECML/PKDD 2007, TON_IoT, CSIC 2010 (secondary sources); CIC-IDS2017 (flows) |
| Command injection | **None** | ECML/PKDD 2007 (OS commanding); AIT (remote command execution via webshell) |
| Credential access | **None** | AIT (password cracking); LANL red team; OTRF/EVTX (reference only) |
| Exfiltration | **None** | AIT (DNSteal); WitFoo (TA0010 on malicious rows in the partial stats) |
| Initial access / execution | **None** | WitFoo (TA0001/TA0002 on positive rows in the partial stats); AIT (webshell upload) |
| Web-shell / exploitation | **None** | AIT (CVE-2020-24186) |
| DoS / DDoS, botnet | **None** | CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, TON_IoT |

**Conclusion:** the existing labelled data covers **0 of the 9 requested attack categories** in a meaningful way. Expansion has to come from new sources; resampling the current data cannot fix this.

## 5. Diversity targets for the proposed integrated dataset

These are acceptance criteria for the next phase. They are not claims about any data yet.

1. **At least 50 distinct positive templates.** No single template may exceed 5% of the positive class after per-template capping.
2. **At least 7 of the 9 categories above** with 100 or more unique positive events each, ideally from 2 or more sources.
3. **Both labels in every source** used for training, or that source is evaluation-only. This stops the model learning "which dataset is this?" as the label.
4. **At least 30% of positives at Tier B** (documented ground truth), so results do not rest only on WitFoo engine labels.
5. **Every row has model-visible text.** Rows with null `raw_log` either get a source-provided structured rendering (see the integration plan) or are excluded from the supervised set.
6. **Benign variety:** cap benign rows per template, e.g. 20 or fewer, so that crond and systemd do not dominate.
