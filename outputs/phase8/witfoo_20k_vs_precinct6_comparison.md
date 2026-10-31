# Existing WitFoo 20K Slice vs WitFoo Precinct6 2M (and 100M)

**Date:** 2026-11-01
**Sources:**
- **Our 20K:** `outputs/supervised_soc_dataset.parquet`, read locally.
- **Precinct6:** the v2.1.0 data cards (README.md) and the Hugging Face file-tree API. Metadata only; **no rows were downloaded**. Hugging Face's column-statistics service for the 2M repo was locked ("try again later"), so no per-column distributions for the 2M are given.

## 1. Side by side

| Aspect | Our 20K slice | Precinct6 2M (v2.1.0) | Precinct6 100M (v2.1.0) |
| :--- | :--- | :--- | :--- |
| **Live signal rows** | 20,000 | 2,011,674 | 114,421,340 |
| **Incident-lead rows** (`incident_signals`) | 0 | 238,511 | 238,511 (same table) |
| **Benign** | 19,956 | 1,897,153 | 113,798,478 |
| **Suspicious** | 44 | 106,793 | 615,134 |
| **Malicious, live** | 0 | **7,728** | 7,728 (same rows) |
| **Malicious, incident leads** | 0 | 238,511 | 238,511 |
| **Time window** | 2024-07-26 11:10:20.7 → 11:21:05.4 UTC (10.7 min) | 2024-07-26 11:10:23 → 2024-08-01 06:00:03 UTC (~5.8 days) | 2024-07-26 11:10:20 → 2024-08-28 00:36:03 UTC (~32.5 days) |
| **Organisations** | Unknown (`org_id` was not kept) | 4 (ORG-0001, -0003, -0004, -0005) | 5 |
| **Columns** | 19 (renamed or derived in Phases 2–5) | 38 | 38 |
| **Columns we lack** | `org_id`, `message_type`, `stream_name`, `matched_rules`, `set_roles`, `label_confidence`, `attack_tactics`/`techniques`, `incident_ids`, `disposition`, `is_false_positive`, `event_time`, `product_name`, … | All present | All present |
| **Dominant streams** | crond 6,337, filebeat 3,586, network_communication 3,126, systemd_logind 1,860, sshd 1,496 | aws_cloudtrail_events 543,159, microsoft-windows-security-auditing 421,587, windows_security_audit 336,425, vcenter 266,201, java_stack_trace 154,465, cisco_asa 95,143 | AWS CloudTrail and Windows Security audit dominate |
| **Positive templates** | 1 | Unknown until profiled | Unknown |
| **Signal files on the Hub** | – | `signals.parquet` 117.1 MB + `incident_signals.parquet` 10.5 MB | 58 shards, 4.37 GB in total |
| **Whole repo, including graph** | – | 7.74 GB | 8.46 GB |

**How the 2M subset was drawn (card):**
1. All 7,728 live malicious leads.
2. Every row from the same organisation within ±5 minutes of an in-window lead: 1,606,249 rows.
3. A uniform random fill of 397,697 rows (fill probability 0.00371, seed 42).

The 2M therefore contains **every malicious row** of the full capture, plus the context around it.

## 2. Is our 20K inside the 2M?

**Not proven either way.** Settling it needs the `artifact_id` column, which has not been downloaded. What the metadata shows:

1. **The start times line up with the 100M, not the 2M.** Our earliest row (11:10:20.72) matches the **100M** capture start (11:10:20). **30 of our rows are earlier than the 2M's first row** (11:10:23), so at least those 30 are not in the 2M v2.1.0 as published.
2. **Our window should contain malicious rows but doesn't.** In v2.1.0, malicious rows appear from 11:15:48. Our window runs to 11:21:05 and has **0 malicious** rows. This fits **either** our slice coming from the **withdrawn v1 release** (2026-05) **or** the 11:15:48 lead belonging to an organisation or stream we did not sample. The card says v1's labelled attacks did not overlap the benign capture in time.
3. **Our stream mix does not look like either release.** Ours is mostly Linux syslog (crond, filebeat, systemd). Both v2 releases are dominated by AWS CloudTrail and Windows audit. In the 100M's first 6M rows, crond has only 32,246 rows. So our slice was probably filtered or drawn from part of the data, not taken as "the first 20,000 rows".
4. **Our `event_id`s are version-1 time UUIDs**, the same form as Precinct's `artifact_id`. The card says v2 keeps artifact UUIDs out of the sanitisation sweep, so **`event_id` = `artifact_id` is the right join key** if the rows are the same.

### Why the version matters
- **v1 was withdrawn** because "some values had escaped sanitization" (device and account names inside escaped Windows event text and in `stream_name`).
- **v1 tokens do not correspond to v2 tokens.** For example, `HOST-0002` in v1 is a different machine from `HOST-0002` in v2.

**If our 20K came from v1:**
- Its `HOST-`/`USER-` tokens cannot be mixed with v2 data. Doing so would merge unrelated machines.
- It may contain values that escaped sanitisation.
- **Recommended:** keep the 20K in the master (unchanged), and **take WitFoo rows only from v2.1.0** for the integrated dataset, matching by `artifact_id` where they overlap.

## 3. What the 2M adds over our 20K

| Gain | Detail |
| :--- | :--- |
| **Malicious rows** | 0 → 7,728 live and 238,511 incident leads, with incident IDs, MO, tactics and disposition |
| **Suspicious rows** | 44 → 106,793, with `matched_rules` and `set_roles` naming *why* each row is suspicious, which is key for measuring template diversity |
| **Organisations** | 4 orgs, so we can do org-grouped leakage control |
| **Event time** | `event_time` from the source product, fixing diversity report Q6 (we currently have ingest time only) |
| **Analyst signals** | `disposition`, `disposition_category`, `is_false_positive`, for the Tier A/C split in the mapping plan |
| **Rule catalogue** | `reference/lead_rules_catalog.json` (0.15 MB): 261 rules, 158 products |

## 4. What the 100M adds over the 2M

- **No extra malicious rows.** The 2M already has all 7,728 live malicious rows, and the `incident_signals` table is identical.
- **About 508,341 extra suspicious rows** (615,134 − 106,793). By organisation:

| Organisation | Suspicious in 100M | Suspicious in 2M |
| :--- | :--- | :--- |
| ORG-0004 | 196,942 | 15,115 |
| ORG-0003 | 3,819 | 113 |
| ORG-0001 | 2,940 | 10 |
| ORG-0005 | 411,433 | 91,555 |

  These are worth having **only if** profiling the 2M shows that its suspicious rows come from too few rules or templates.
- **More benign variety.** This is not needed: benign data is already plentiful.

**Conclusion:** the 2M **signal tables (about 128 MB)** give almost all of the value. The 2M graph files (7.7 GB) are not needed for event classification. The 100M is a conditional, selective extra.
