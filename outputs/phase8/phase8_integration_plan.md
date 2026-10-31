# Phase 8: Proposed Integration Plan

**Status:** Proposal. **Nothing below has been run.** Each stage needs your approval before it starts.
**Related documents:** `phase8_dataset_source_research.md`, `phase8_dataset_source_inventory.csv`, `phase8_label_mapping_plan.md`, `phase8_diversity_gap_report.md`

## 1. Protected artefacts (never modified)

Each later stage re-checks these SHA-256 values at start and end, and stops if any of them changes.

| File | SHA-256 |
| :--- | :--- |
| `outputs/merged_soc_dataset.csv` (120,000-row master) | `02b68ed407bfa899c748bbde1e97bf92ee708f796cde88c57a145af287382ed9` |
| `outputs/merged_soc_dataset.parquet` | `d5583cdb997b923d02f824a13891a7769f23df066d5e3c3f329d82a1d56ba1c6` |
| `outputs/merged_soc_dataset.jsonl` | `541db5bb81c62f1712b9dd6cedc8117e23e8b82b7fcae9e662b34136376e2fff` |
| `outputs/merged_soc_dataset_balanced.csv` (Phase 7) | `22b81510bd747d2d95396ce355231814ea7e39dda92097370b0ed43a12465797` |
| `outputs/merged_soc_dataset_balanced.parquet` | `7c5f6a34c94fe4f013c97eeb09a2aaf120f775da3306454dea2d1c8e105dcea3` |
| `outputs/merged_soc_dataset_balanced.jsonl` | `ed40158d6f21c81e0ae3fa014b9d12a0c2a9d47d15b61d71830e1a4d6165849f` |
| `outputs/supervised_soc_dataset.parquet` | `8c734bd44190e260c1a8ad968d7182826c5e2049a90edc98014f07651a87bd8f` |

`outputs/phase8/phase8_existing_data_assessment.json` records the full list, including the deduplicated files.

## 2. Folder layout

```
dataset/external/                      # NEW: raw downloads, read-only after the manifest is written
  README.md
  <SOURCE_ID>/raw/...                  # files exactly as downloaded
  <SOURCE_ID>/MANIFEST.sha256          # written immediately after download
  <SOURCE_ID>/SOURCE.md                # URL, version, licence, download date, citation
outputs/phase8/                        # Phase 8 reports (this folder)
  normalised/<SOURCE_ID>.parquet       # 8c: one file per source in the unified schema, labels mapped
  review/                              # 8c/8d: manual label samples, held-out conflicts
outputs/phase8_integrated/             # NEW: proposed integrated candidate (8e), NOT a train/test split
  README.md
```

`dataset/external/` should be added to `.gitignore`, because AIT-LDS alone is 130 GB. The manifests and `SOURCE.md` files are kept in git.

## 3. Stages and approval gates

| Stage | Work | Output | Gate |
| :--- | :--- | :--- | :--- |
| **8a** *(done)* | Assessment, source research, mapping and plan | These 5 documents | **Your approval now** |
| **8b** | Acquire Tier 1 sources in order: (1) WitFoo 2M, all `signals` + `incident_signals`; (2) AIT-ADS (96 MB); (3) AIT-LDS V2, one testbed (`russellmitchell`, 7.1 GB); (4) CSIC 2010 once its licence is confirmed | `dataset/external/*` plus manifests | You approve the source list and disk budget |
| **8b-profile** | Profile only, no labelling: label counts against the published counts; template, rule and stream counts per label; and for WitFoo, positives per `matched_rules`, `stream_name`, `org_id` and tactic | `phase8b_source_profile.md` | Go/no-go per source. Decide whether WitFoo 100M shards are worth fetching for more positive variety. |
| **8c** | Normalise into the unified schema (§5) and apply the mapping rules. Write `label_evidence.md` quoting each source's label definition. Draw 50-row manual samples per label value. | `outputs/phase8/normalised/*`, `review/*` | You review the label samples |
| **8d** | Duplicate, near-duplicate, conflict and leakage checks (§4) | `phase8d_dedup_leakage_report.md` | You approve the dedup and capping decisions |
| **8e** | Build the **proposed integrated candidate**: union of normalised sources, dedup flags applied, group keys assigned. **No train/test split.** | `outputs/phase8_integrated/` plus a datasheet | Your approval before any split |
| *(later)* | Split design, notebook feature redesign, fine-tuning | – | Out of scope for Phase 8 |

**Tier 2 sources** (ECML/PKDD 2007, Improved CIC-IDS2017, BETH, TON_IoT, LANL) are added at 8b only if 8b-profile shows a gap the Tier 1 sources do not fill.

## 4. Duplicate and leakage checks (Stage 8d)

We **flag** problems and **cap** repetition. We do **not** delete valid separate events from the normalised files. All removals happen as filters in 8e and are listed with reasons.

### 4.1 Exact duplicates
| Check | Key | Action |
| :--- | :--- | :--- |
| Same record, same source | `source_dataset + source_record_id` | Keep one; record the count |
| Same record, different releases | WitFoo `artifact_id` (UUIDs are kept through sanitisation); our existing `event_id`s are UUIDs too | Link existing Dataset 2 rows to WitFoo 2M/100M rows. `incident_signals` appears in both releases (238,511 rows each), so ingest it once. |
| Same content, different IDs | SHA-256 of `raw_log` with only `\x00` and whitespace normalised, plus `source_dataset` | Flag `exact_content_dup_group`. Count it as a separate event if timestamps differ; it is still a real event. |
| Cross-source identical content | Same hash across sources (e.g. CSIC mirrors versus the original) | Keep the official-source copy; note the mirror |

### 4.2 Near-duplicate templates
- **Method.** Mask variable tokens (timestamps, HOST/USER tokens, IPs, UUIDs, hex, numbers), as `scripts/assess_phase8.py:template()` does. Optionally cluster with Drain3 per source, which gives a `template_id`.
- **Report.** For each template: rows, labels, sources and hosts.
- **Cap per template**, so that one template cannot dominate:
  - Positives: no more than 5% of the positive class per template.
  - Benign: no more than 20 rows per template per source. Both caps are to be confirmed after profiling.
  - Rows over a cap stay in the normalised files, with `in_candidate = false`.
- The existing 44 rows become a single `template_id`, so at most a capped number of them are used. **They are never duplicated.**

### 4.3 Conflicting labels
| Case | Handling |
| :--- | :--- |
| The same `raw_log` hash has both labels within one source | Flag `label_conflict`. For WitFoo this is expected (labels depend on context), so tag it `context_dependent_label` and report counts. Exclude it from the candidate if the conflict rate in a template is over 10%. |
| The same template has both labels | Keep both, as these are informative hard pairs. Make sure they land in the **same** split group (§4.5), so the model is not tested on a template whose opposite-label twin it trained on. |
| A source's own fields disagree (WitFoo `is_false_positive`, analyst dispositions) | Hold out, per mapping rule `WF-X1` |
| AIT-ADS alert on a window boundary | Unlabelled, per `ADS-N` |

### 4.4 Host and source shortcuts
Measure each of the following against the label: Cramér's V, and the accuracy of a one-feature classifier.
- **Fields:** `host` token, `org_id`, `source_dataset`, `stream_name`/`source`, `event_type`, syslog PRI, severity, NUL suffix, and sanitised IP ranges (RFC 5737 TEST-NET).
- **Threshold.** Any single field that predicts the label with more than 90% accuracy *within a source* is a shortcut. Remove it from the model input, or mask it in the input text only; `raw_log` itself stays unchanged.
- **Per-source label ratio.** A source with only one class (for example a positives-only LANL extract) is evaluation-only. Otherwise the model learns "this source means attack".
- **Already identified:** `event_type`, the HOST-0002/0006 tokens, PRI `<142>`/`<141>`, and the trailing NUL (diversity report Q2 and Q11).

### 4.5 Leakage prevention for the future split
This stage only *assigns* the keys. **No split is created.**
- `split_group_key = source_dataset + template_id + host_group`. Rows sharing a key must always fall in the same split. `host_group` is the host token, or `org_id` for WitFoo, or the testbed for AIT.
- `time_block`: day-level blocks from **event** time, not WitFoo ingest time (diversity report Q6). This allows a time-ordered split if wanted.
- `campaign_key` for multi-step attacks (WitFoo `incident_ids`; AIT scenario and attack phase), so that one intrusion is not split across train and test.
- **Recommended later:** hold out at least one whole source and one whole AIT testbed for cross-domain testing.

## 5. Unified schema

The existing 19 columns are kept with the same names and meaning: `event_id, timestamp, timestamp_raw, event_type, source, severity, source_ip, dest_ip, source_port, dest_port, protocol, protocol_raw, user, raw_log, label, label_text, label_raw, label_source, data_origin`.

New columns are added from the mapping plan §3: `source_dataset, source_version, source_file, source_record_id, original_label, original_label_field, original_attack_category, mapped_label, mapping_rule_id, label_evidence_tier, label_confidence_source, raw_record_json, timestamp_semantics, data_nature, license, provenance_url, download_date, source_file_sha256`.

Plus these for 8d/8e: `template_id, exact_content_dup_group, label_conflict, context_dependent_label, host_group, split_group_key, time_block, campaign_key, in_candidate, exclusion_reason`.

**How the columns relate:**
- `label` is set equal to `mapped_label`.
- `label_raw` is set equal to `original_label`.
- `data_origin` gets one value per source (e.g. `witfoo_production_sanitised`, `ait_lab_testbed`).

**Rows without log text** (flows, LANL CSV, BETH process calls) keep `raw_log` exactly as the source gives it: the original CSV line where there is one, otherwise null. They also get a separate `model_text` field. `model_text` is a fixed `key=value` rendering of fields the source already contains. It is a formatting step only: no values are added or inferred. It is **not** written into `raw_log`, so it is never mistaken for an original log.

## 6. How existing data enters the candidate

| Existing data | Treatment |
| :--- | :--- |
| 19,956 benign (Dataset 2) | Included through the 4,260 unique rows, linked to WitFoo `artifact_id` if matched, and capped per template. Label tier C. |
| 44 suspicious (Dataset 2) | Included as **one template cluster** under the positive cap. Tier C. Never duplicated. |
| 100,000 unlabelled (Dataset 1, synthetic) | **Excluded** from the supervised candidate. It stays in the master unchanged. |
| Phase 7 balanced (484) | Untouched. Kept only as the historical proof-of-concept baseline. |

## 7. Note on the fine-tuning notebook (for the later phase)

`training/SIEM_Qwen3_4B_finetune.ipynb` builds its prompt from `log_source, dest_port, method, url, status_code, bytes, user, auth_method, user_agent`, and drops `raw_log` as "leaky". With our schema, that would drop **every** positive row (diversity report Q3). Before any fine-tuning, the input should be redesigned:
- Feed the model a cleaned `raw_log` / `model_text`, with shortcut tokens masked per §4.4.
- Keep `MAX_SEQ_LEN = 512` in mind: Windows XML and CloudTrail JSON in WitFoo may need truncation rules.

Nothing in the notebook has been changed.

## 8. Risks and open questions for you

1. **Label strength.** WitFoo positives are engine labels (Tier C). Do you accept them as positives, or should your final evaluation report Tier B results separately? Reporting them separately is recommended.
2. **Licence.** Including AIT-LDS makes the integrated candidate CC-BY-NC-SA. Is non-commercial acceptable for your project and model?
3. **Disk and time.** AIT-ADS (96.2 MB) plus one AIT-LDS testbed (7.1 GB compressed) is about 7.2 GB, before WitFoo 2M is added; its size is not stated on its card and will be checked before download. Is that within budget?
4. **CSIC 2010 / ECML-PKDD 2007** have no stated licence. Should I ask the authors, or use them with citation and mark the licence as unconfirmed?
5. **Positive variety from WitFoo.** The partial statistics show narrow tactics (TA0001, TA0002, TA0009, TA0010) in the first 6M rows. The 8b-profile stage will show whether WitFoo alone gives enough distinct templates. If not, the AIT, CSIC and ECML sources become essential, not optional.
