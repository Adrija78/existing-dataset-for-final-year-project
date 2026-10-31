# Phase 8: Labelled SOC Dataset Source Research

**Status:** Research only. No dataset has been downloaded, integrated or relabelled. Waiting for approval.
**Date of research:** 2026-10-31
**Machine-readable inventory:** `phase8_dataset_source_inventory.csv` (19 sources, same order as below)

## 1. How this research was done

- Every figure below was taken from the source's official page, data card or the authors' paper, fetched on 2026-10-31. The verification URL for each source is in the inventory `verified_from` column.
- If a page did not give a figure, the inventory says **"not stated on official page; count after download"**. No missing figure was estimated.
- Some figures come from secondary sources (mirrors or papers) because the official page could not be reached or did not give them. These are marked as such.
- For WitFoo I also queried the Hugging Face `datasets-server` column-statistics endpoint. It returns aggregate metadata only, not rows. That result is **partial**, covering the first 6,000,000 signal rows of the 100M release.

## 2. What we need from a source

From the Phase 6/7 findings and the Qwen3-4B goal, a useful source must:

1. Contain **real or independently validated events**, not generator output. The existing Dataset 1 is synthetic (§3.19).
2. Carry **per-event labels that come from the source**. We will not create labels ourselves.
3. Contain **log text or alert text**, so the model sees `raw_log`-style input. Flow-feature-only data is a weaker fit.
4. Add **attack categories we currently lack**. Right now there is effectively one template (§ diversity report).
5. Have a **licence** that allows academic use in a final-year project.

## 3. Candidate sources

### 3.1 WitFoo Precinct6 Cybersecurity (2M), v2.1.0. Tier 1
- **Source:** WitFoo, https://huggingface.co/datasets/witfoo/precinct6-cybersecurity
- **Records:** `signals` 2,011,674 and `incident_signals` 238,511, combined 2,250,185.
- **Labels (combined):** benign 1,897,153 (84.31%), suspicious 106,793 (4.75%), malicious 246,239 (10.94%).
- **Fields:** `label_binary`, `label_confidence`, `suspicion_score`, `matched_rules`, `set_roles`, `attack_techniques`, `attack_tactics`, `disposition`, `disposition_category`, `is_false_positive`, `message_sanitized`, `src_ip`/`dst_ip`/ports, `username`, `org_id`, `artifact_id` and others.
- **How labels are made (data card):** *malicious* means the row is the triggering lead of a Precinct incident. *Suspicious* means it matched one or more of WitFoo's 261 lead-detection rules but is not an incident lead. *Benign* means no rule matched. The card states plainly that **there is no independent, analyst-verified ground truth**. Analyst dispositions such as Confirmed-malicious, False Positive and Dismissed are rare.
- **Format and licence:** Parquet signals; NDJSON incidents and graph. **Apache-2.0.**
- **Fit:** This is the same product our Dataset 2 came from. The card says the 2M release is a deterministic subset of the 100M capture, built around incidents, with sanitisation tokens shared across both releases.

### 3.2 WitFoo Precinct6 Cybersecurity (100M), v2.1.0. Tier 1 (selected shards)
- **Source:** https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m (58 parquet shards)
- **Records:** signals 114,421,340, incident_signals 238,511, graph_edges 101,328,727, graph_nodes 67,166, attack_reports 51,371.
- **Labels (signals):** benign 113,798,478, suspicious 615,134, malicious 7,728. incident_signals: 238,511, all malicious.
- **Partial statistics, first 6M signal rows:** benign 5,963,923, suspicious 33,157, malicious 2,920. Only two dispositions appear: Unprocessed 5,997,477 and Disrupted 2,523. The only MO is "Data Theft", on 2,920 rows. Tactic sets: `[TA0001, TA0002]` 33,117; `[TA0001, TA0002, TA0009, TA0010]` 2,920; `[TA0009, TA0010]` 40. **Positive labels in this slice therefore cover a narrow tactic range.** Diversity has to be profiled before we commit to a download.
- **Capture window:** 2024-07-26 to 2024-08-28. Our Dataset 2 timestamps (2024-07-26 11:10–11:21) sit at the very start of that window. This fits our 20,000 rows being an early slice of `signals`, but it does not prove it.
- **Caveat:** press coverage quotes different benign and malicious percentages from the card. I used the card figures.

### 3.3 AIT Log Data Set V2.0. Tier 1
- **Source:** AIT Austrian Institute of Technology (Landauer et al., IEEE TDSC 2022), https://zenodo.org/records/5789064
- **Size:** 8 testbeds, 130.6 GB compressed. The individual zips range from 7.1 GB (russellmitchell) to 26.5 GB (wilson). **The record page gives no line count.**
- **Labels:** line-level JSON pointing at attack-related log lines, built by rule-matching the known, scripted attack behaviour.
- **Attacks:** nmap/WPScan/dirb scans, webshell upload (CVE-2020-24186), password cracking, privilege escalation, remote command execution, DNS exfiltration.
- **Format:** raw Apache access/error, auth, DNS, VPN, audit, Suricata, Exim, Horde, syslog and monitoring logs, plus PCAP.
- **Licence:** **CC-BY-NC-SA-4.0.** Non-commercial, and share-alike carries over to any dataset derived from it.
- **Fit:** the best raw-log fit for privilege escalation, credential attacks and command execution. It is a lab testbed with simulated users, not production.

### 3.4 AIT Alert Data Set (AIT-ADS). Tier 1
- **Source:** https://zenodo.org/records/8263181, v1 (2023-08-18)
- **Records:** 2,655,821 alerts: Wazuh 2,293,628, Suricata 306,635, AMiner 55,558.
- **Labels:** `labels.csv` with the start and end time of each attack phase per scenario. **Alerts are not labelled one by one.**
- **Attacks:** as AIT-LDS V2, plus a stopped-service phase.
- **Format and licence:** JSON alerts, 96.2 MB zip. **CC-BY-4.0.**
- **Fit:** these are genuine IDS alert formats. Alerts that fall outside attack windows could be useful false-positive examples, but only if the paper confirms that interpretation (see the label mapping plan).

### 3.5 HTTP Dataset CSIC 2010. Tier 1 for web attacks, if the licence is confirmed
- **Source:** CSIC (Spain), https://www.tic.itefi.csic.es/dataset/. **The official site refused the connection during research.**
- **Records (secondary sources):** about 36,000 normal and more than 25,000 anomalous requests. A Hugging Face mirror has 61,792 rows.
- **Labels:** by subset file (normal or anomalous).
- **Attacks (secondary sources):** SQL injection, buffer overflow, information gathering, file disclosure, CRLF injection, XSS, parameter tampering.
- **Licence:** **not stated.** The Kaggle mirror lists "Data files © Original Authors".
- **Fit:** raw HTTP requests, which map directly onto the notebook's `method`, `url` and `user_agent` features. The traffic was **generated automatically by the authors**, so it must be tagged lab-generated. Also, "anomalous" is not the same as "confirmed attack".

### 3.6 ECML/PKDD 2007 Discovery Challenge (web traffic). Tier 2
- **Source:** LIRMM, https://www.lirmm.fr/pkdd2007-challenge/
- **Records (secondary source):** 35,006 normal and 15,110 attack. Other descriptions give conflicting train/test attack ratios, so this **must be checked against the files**.
- **Labels:** valid, or one of 7 classes: XSS, SQL injection, LDAP injection, XPath injection, path traversal, OS command execution, SSI.
- **Licence:** **not stated.**
- **Fit:** the only verified source here with labelled **command-injection** HTTP requests.

### 3.7 Improved CIC-IDS2017 (DistriNet, KU Leuven). Tier 2
- **Source:** https://downloads.distrinet-research.be/WTMC2021 (Engelen, Rimmer & Joosen, 2021)
- **What changed:** the authors re-extracted flows with a fixed CICFlowMeter and relabelled. They report removing artefacts that made up about 20% of the data and correcting labels on about 10% of samples.
- **Records and licence:** **not verified.**
- **Fit:** flow features only, with no log text. If any CIC-IDS2017 data is used, use this version instead of the original.

### 3.8 CIC-IDS2017 (original). Tier 3
- **Source:** UNB CIC, http://cicresearch.ca/CICDataset/CIC-IDS-2017/
- **Size:** 51.1 GB over 5 days. The page gives no flow count.
- **Attacks:** FTP/SSH brute force, DoS variants, Heartbleed, web brute force, XSS, SQLi, infiltration, botnet, port scan, DDoS.
- **Format and terms:** PCAP plus CSV with 80+ flow features. Free to use with citation.
- **Caveat:** labelling and flow-construction errors are documented (§3.7).

### 3.9 CSE-CIC-IDS2018. Tier 3
- **Source:** AWS `s3://cse-cic-ids2018/`
- **Contents:** PCAP, CSV flows, and **per-machine Windows and Ubuntu event logs**.
- **Attacks:** brute force, Heartbleed, botnet, DoS, DDoS, web attacks, infiltration.
- **Terms:** redistribution allowed with citation.
- **Caveat:** the host logs are **not labelled per event**, and the page gives no record count.

### 3.10 UNSW-NB15. Tier 3
- **Records:** 2,540,044 in total. The official training and testing sets have 175,341 and 82,332.
- **Labels:** `label` plus `attack_cat` with 9 categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.
- **Terms:** free for academic research; commercial use needs agreement; 5 papers must be cited.
- **Fit:** flow features only.

### 3.11 TON_IoT. Tier 2
- **Contents:** IoT/IIoT telemetry, Windows 7/10 and Ubuntu audit traces, and network data.
- **Labels:** `label` and `type`. Attacks: scanning, DoS, DDoS, ransomware, backdoor, **data** injection, XSS, password cracking, MITM.
- **Terms:** free for academic research; cite 8 papers.
- **Gaps:** **record counts not verified.** "Injection" here means data injection against telemetry, not command injection.

### 3.12 LANL Comprehensive Multi-Source Cyber-Security Events (2015). Tier 2, positives only
- **Records:** 1,648,275,307 events over 58 days. `redteam.txt.gz` is 4.8 KB of known red-team compromise events taken from the auth data.
- **Licence:** **CC0-1.0.**
- **Caveat:** only red-team events are labelled. **Every other event is unlabelled, not benign.** Mapping background events to 0 would be inventing labels.

### 3.13 BETH (BPF-extended tracking honeypot). Tier 2
- **Records:** 8,004,918 events from 23 cloud honeypots, about 5 hours.
- **Labels:** hand-crafted `sus` and `evil` columns. This maps naturally onto our suspicious and malicious split. `evil` appears only in the test portion.
- **Format and licence:** CSV of kernel process calls and DNS. **CC0** (Kaggle).
- **Caveat:** these are honeypots, so the benign activity is system background only.

### 3.14 UWF-ZeekData22. Tier 3
- **Records:** 18,562,468: attack 9,280,869, benign 9,281,599.
- **Tactics:** Reconnaissance 9,278,722, Discovery 2,086, and **59 rows** across 8 other tactics. Positives are almost entirely recon.
- **Licence:** the dataset licence is not stated (the article is CC BY).

### 3.15 OTRF Security Datasets (formerly Mordor). Reference only
- **Contents:** 100+ Windows atomic datasets, plus Linux, AWS and compound scenarios. JSON Windows Security and Sysmon logs. **MIT.**
- **Why reference only:** labels are **per dataset** (the simulated technique), and each recording mixes attack events with background noise. Per-event labels would need analyst review.

### 3.16 EVTX-ATTACK-SAMPLES. Reference only
- **Contents:** about 200 EVTX files organised by ATT&CK tactic, labelled per file. **GPL-3.0** (copyleft).
- **Why reference only:** same limitation as OTRF.

### 3.17 Splunk BOTSv1. Reference only
- **Contents:** **CC0**, 22 sourcetypes, 6.1 GB compressed indexed.
- **Why reference only:** no per-event labels. Useful later as a realistic evaluation corpus.

### 3.18 Loghub (OpenSSH 655,146, Linux 25,567, Apache 56,481 lines). Rejected as a labelled source
- These three logs are unlabelled. The Loghub sets that do have labels (HDFS, BGL, Thunderbird) mark operational anomalies, not security events. Labelling the SSH failures ourselves would mean making up labels.

### 3.19 Advanced_SIEM_Dataset (our existing Dataset 1). Rejected as a genuine source
- Its Hugging Face card describes it as **synthetic**. Our audit shows its timestamps run from 2020-07-12 to 2030-07-10.
- This matters because the "100,000 additional unlabelled events" in the master dataset are this data. They are generator output, not observed events, and should not be labelled or treated as genuine SOC data. **The master dataset is left unchanged.**

## 4. Summary ranking

| Tier | Sources | Why |
| :--- | :--- | :--- |
| **1** | WitFoo 2M, then WitFoo 100M shards; AIT-LDS V2; AIT-ADS; CSIC 2010 (if licence confirmed) | Real or documented-ground-truth events, log/alert text, the categories we lack, workable licences |
| **2** | ECML/PKDD 2007, Improved CIC-IDS2017, TON_IoT, BETH, LANL (positives only) | Useful categories, but with gaps in licence, format or label semantics |
| **3** | CIC-IDS2017 original, CSE-CIC-IDS2018, UNSW-NB15, UWF-ZeekData22 | Flow-only, known label errors, or one dominant class |
| Reference | OTRF, EVTX-ATTACK-SAMPLES, BOTSv1 | No per-event labels |
| Rejected | Loghub (security logs), Advanced_SIEM_Dataset | Unlabelled or synthetic |

## 5. Licence implications

- **Mixed licences.** An integrated dataset that includes AIT-LDS (CC-BY-NC-SA) becomes non-commercial and share-alike. UNSW-NB15 and TON_IoT are academic-only, and EVTX samples are GPL-3.0. Each record's licence must therefore be kept in the record, and the proposed integrated dataset must state the most restrictive terms that apply to it.
- **Model weights.** A model fine-tuned on NC-licensed data should be treated as research-only.
- **Confirm before download.** CSIC 2010 and ECML/PKDD 2007 have no stated licence. Ask the authors, or record them as "use with citation, licence unconfirmed", before downloading.

## Sources

- [WitFoo Precinct6 Cybersecurity (2M)](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity)
- [WitFoo Precinct6 Cybersecurity (100M)](https://huggingface.co/datasets/witfoo/precinct6-cybersecurity-100m)
- [AIT Log Data Set V2.0 (Zenodo)](https://zenodo.org/records/5789064)
- [AIT Alert Data Set (Zenodo)](https://zenodo.org/records/8263181)
- [CSIC 2010 official page](https://www.tic.itefi.csic.es/dataset/), [HF mirror](https://huggingface.co/datasets/bridge4/CSIC2010_dataset_classification)
- [ECML/PKDD 2007 challenge](https://www.lirmm.fr/pkdd2007-challenge/), [challenge description](https://hal-lirmm.ccsd.cnrs.fr/lirmm-00168955)
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)
- [Engelen et al. 2021, Troubleshooting CICIDS2017](https://lirias.kuleuven.be/retrieve/713070)
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset), [TON_IoT](https://research.unsw.edu.au/projects/toniot-datasets)
- [LANL cyber1](https://csr.lanl.gov/data/cyber1/)
- [BETH (Kaggle)](https://www.kaggle.com/datasets/katehighnam/beth-dataset)
- [UWF-ZeekData22 paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC9610873/), [datasets.uwf.edu](https://datasets.uwf.edu)
- [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), [securitydatasets.com](https://securitydatasets.com/introduction.html)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [Splunk BOTSv1](https://github.com/splunk/botsv1)
- [Loghub](https://github.com/logpai/loghub)
- [Advanced_SIEM_Dataset](https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset)
