# Phase 8: Label Verification and Binary Mapping Plan

**Status:** Proposed. Nothing has been mapped yet. Every rule below waits on approval and on checking it against the downloaded files.

## 1. Target label

| `mapped_label` | Meaning |
| :--- | :--- |
| `0` | **Benign.** The source asserts the event is normal: no detection, outside every attack, or explicitly marked normal. |
| `1` | **Suspicious or malicious alert.** The source asserts the event matched a detection, belongs to a documented attack, or is explicitly marked attack, suspicious or malicious. |
| *(null)* | **Unlabelled.** The source makes no claim either way. These records are never put in the supervised set. |

**Core rule:** a record gets `0` only when the source *positively* says it is benign. Being absent from an attack list is not enough. For example, LANL background events stay null and are never set to 0.

## 2. Label evidence tiers

Each mapped record carries a `label_evidence_tier`, so the model can later be evaluated per tier and weak labels can be dropped if needed.

| Tier | Evidence | Sources |
| :--- | :--- | :--- |
| **A** | An analyst confirmed it for that event | WitFoo rows with an analyst disposition (Confirmed-malicious; rare) |
| **B** | Documented ground truth from a controlled experiment: scripted attack schedule, red-team log or per-line labels | AIT-LDS V2, CSIC 2010, ECML/PKDD 2007, Improved CIC-IDS2017, UNSW-NB15, TON_IoT, LANL red team, BETH |
| **B-window** | Ground truth only as an attack time window, not per event | AIT-ADS |
| **C** | Automated detection engine or rule match, with no independent check | WitFoo `label_binary` (all of our existing Dataset 2, including the 44 suspicious rows) |

**Our existing 44 suspicious rows are Tier C.** The WitFoo data card says its labels come from the Precinct correlation engine with no analyst-verified ground truth. Our existing labels are therefore engine output, not confirmed attacks.

## 3. Columns kept for every record

| Column | Content |
| :--- | :--- |
| `source_dataset` | Inventory `source_id`, e.g. `WITFOO_2M`, `AIT_LDS_V2` |
| `source_version` | Release, data-card version or Zenodo version |
| `source_file` | Original file or shard name, plus row or line number |
| `source_record_id` | The source's own ID (`artifact_id`, line number, CIC flow ID, etc.), stored exactly as given |
| `event_id` | Our ID: the source ID if it is globally unique, else `"{source_dataset}:{source_file}:{row}"` |
| `original_label` | The source label exactly as published, e.g. `suspicious`, `Anomalous`, `SSH-Patator`, `evil=1` |
| `original_label_field` | Which column or file the label came from |
| `original_attack_category` | The source's attack class or tactic, unchanged |
| `mapped_label` | 0 / 1 / null, per §4 |
| `mapping_rule_id` | The rule in §4 that produced it |
| `label_evidence_tier` | A / B / B-window / C |
| `label_confidence_source` | The source's own confidence where it has one (WitFoo `label_confidence`) |
| `raw_log` | The original log line, alert JSON or request text, verbatim (NUL bytes kept and flagged, not stripped) |
| `raw_record_json` | The full original record serialised, so no source field is lost |
| `timestamp` / `timestamp_raw` | Parsed UTC time plus the original string |
| `timestamp_semantics` | `event_time`, `ingest_time` or `relative_epoch` (LANL) |
| `data_nature` | `production_sanitised`, `lab_testbed`, `honeypot`, `lab_generated_requests` or `synthetic` |
| `license` | Licence of this record's source |
| `provenance_url`, `download_date`, `source_file_sha256` | Where it came from and proof that it has not changed |

## 4. Mapping rules per source

Each rule will be checked against the downloaded documentation and a manual sample of at least 50 rows per original label value before it is applied.

### Existing Dataset 2 (WitFoo slice): retained as is
| Rule | Original | Mapped | Tier |
| :--- | :--- | :--- | :--- |
| `WF-0` | `benign` | 0 | C |
| `WF-1` | `suspicious` | 1 | C |

The 44 suspicious rows **keep label 1**, because the source asserts it. They are also tagged `single_template_cluster = true` so they cannot dominate the positive class (see the diversity report).

### WitFoo 2M / 100M
| Rule | Condition | Mapped | Tier |
| :--- | :--- | :--- | :--- |
| `WF-0` | `label_binary == benign` | 0 | C |
| `WF-1` | `label_binary == suspicious` | 1 | C |
| `WF-2` | `label_binary == malicious` (incident lead) | 1 | C (A if analyst-confirmed) |
| `WF-X1` | `is_false_positive == true`, or an analyst disposition of False Positive or Dismissed | **held out**: kept in a review file and excluded from the supervised set | – |
| `WF-X2` | The same `artifact_id` appears in both `signals` and `incident_signals` | One record kept; both origins recorded | – |

**Why `WF-X1` holds rows out instead of relabelling them to 0:** the engine's label and the analyst's disposition disagree. Choosing one would be our decision, not the source's. Held-out counts will be reported.

**Context-dependent labels:** WitFoo marks a row suspicious or malicious because of correlation context (rules, incident membership), not text alone. Identical `message_sanitized` text can legitimately carry different labels. These cases are flagged `context_dependent_label = true`, not deleted (see the integration plan §4).

### AIT-LDS V2
| Rule | Condition | Mapped | Tier |
| :--- | :--- | :--- | :--- |
| `AIT-1` | The line is referenced in the labels JSON | 1 | B |
| `AIT-0` | The line is not referenced, **and** the documentation confirms the labelling covers that log file completely | 0 | B |
| `AIT-N` | Neither condition holds | null | – |

**To verify first:** whether the dataset paper says the unreferenced lines in each labelled file are normal.

### AIT-ADS
| Rule | Condition | Mapped | Tier |
| :--- | :--- | :--- | :--- |
| `ADS-1` | The alert time falls inside an attack-phase window in `labels.csv` for that scenario | 1 | B-window |
| `ADS-0` | The alert is outside every window, **and** the paper confirms no attacker activity there | 0 (`original_label = false_positive_alert`) | B-window |
| `ADS-N` | Otherwise, or ambiguous at a window boundary (±60 s, to be tuned) | null | – |

`ADS-0` rows would be hard negatives: real IDS alerts triggered by benign activity. This is valuable, but only if the documentation supports it.

### CSIC 2010
| Rule | Condition | Mapped | Tier |
| :--- | :--- | :--- | :--- |
| `CSIC-0` | Request from a normal file | 0 | B |
| `CSIC-1` | Request from an anomalous file | 1 | B |

Keep `original_label = anomalous`. The model card must state that "anomalous" includes every request the authors marked as anomalous, which is not necessarily a confirmed attack. Tag `data_nature = lab_generated_requests`.

### ECML/PKDD 2007
| Rule | Condition | Mapped | Tier |
| :--- | :--- | :--- | :--- |
| `PKDD-0` | Class `Valid` | 0 | B |
| `PKDD-1` | Any of the 7 attack classes | 1 | B |

Keep the class name in `original_attack_category`.

### Improved CIC-IDS2017, CSE-CIC-IDS2018 (flows), UNSW-NB15, TON_IoT
| Rule | Condition | Mapped |
| :--- | :--- | :--- |
| `FLOW-0` | Benign or normal class / `label == 0` | 0 |
| `FLOW-1` | Any named attack / `label == 1` | 1 |
| `FLOW-R` | The source marks a flow as an attempted or failed attack, or as an artefact | Original label kept; held out for review |

**CSE-CIC-IDS2018 host event logs:** null. They are not labelled per event.

### LANL 2015
| Rule | Condition | Mapped |
| :--- | :--- | :--- |
| `LANL-1` | The auth event matches a `redteam.txt` row on (time, user, src computer, dst computer) | 1 (B) |
| `LANL-N` | Every other event | **null, never 0** |

### BETH
| Rule | Condition | Mapped |
| :--- | :--- | :--- |
| `BETH-0` | `sus == 0` and `evil == 0` | 0 |
| `BETH-1S` | `sus == 1` and `evil == 0` | 1 (`original_label = suspicious`) |
| `BETH-1M` | `evil == 1` | 1 (`original_label = malicious`) |

### UWF-ZeekData22
| Rule | Condition | Mapped |
| :--- | :--- | :--- |
| `UWF-0` | Benign | 0 |
| `UWF-1` | Any MITRE tactic label (tactic kept) | 1 |

### OTRF, EVTX-ATTACK-SAMPLES, BOTSv1, Loghub, Advanced_SIEM_Dataset
**Not mapped.** None of these has a per-event label, and Advanced_SIEM_Dataset is synthetic. They are kept, if acquired at all, as reference or evaluation material only.

## 5. Verification steps before applying any rule

1. **Read the documentation.** Read each source's paper or README section on labels and quote the defining sentence in `phase8b_label_evidence.md`.
2. **Check counts.** Confirm the label counts in the files match the published counts. Any mismatch over 0.5% stops that source until explained.
3. **Inspect samples manually.** Review 50 random rows per original label value, plus 50 from the smallest attack class, and record agreement in a review sheet. If more than 10% of a positive class looks plainly benign (or the reverse), escalate before use. **Labels are never edited.**
4. **Check conflicts.** Find identical `raw_log` text with different `mapped_label` values within a source and across sources (integration plan §4).
5. **Keep a manifest.** Record the SHA-256 of every downloaded file in `dataset/external/<source_id>/MANIFEST.sha256` before any parsing.

## 6. What this plan will not do

- Infer labels from keywords. For example, "Failed password" is **not** turned into 1.
- Change labels to "correct" a source. Disagreements are reported and the rows held out.
- Add the synthetic Dataset 1 rows to the supervised set.
- Create synthetic positives, oversample, or duplicate the 44 suspicious rows.
