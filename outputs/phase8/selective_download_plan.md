# Phase 8: Selective Download and Storage-Efficient Processing Plan

**Status:** Proposal. **Nothing has been downloaded.** Each step needs your approval.
**Constraints:** 39.9 GB free on the internal SSD, 16 GB RAM, no external storage.
**Budget:** 20 GB hard cap on project growth, with at least 15 GB always left free (`storage_audit.md` §1).
**Related:** `storage_audit.md`, `witfoo_20k_vs_precinct6_comparison.md`, `phase8_integration_plan.md`

## 1. Principles

1. **Download files, not repos.** Fetch named files only, never a whole dataset repo.
2. **Keep one copy of each original.** Raw files go in `dataset/external/<SOURCE_ID>/raw/`. Each gets a SHA-256 manifest and is then set read-only. No second copy goes into a cache.
3. **One output format.** New outputs are **Parquet with zstd compression only**. CSV or JSONL is exported only when you ask for it (the Colab notebook already reads `.parquet`).
4. **Process in batches.** Use pyarrow `iter_batches` with column projection, so the whole table is never in RAM.
5. **Point, don't copy.** Normalised rows store a *pointer* to the original (`source_file`, `row_index`, `artifact_id`) instead of a full copy of the record. This is safe because the originals are kept. It changes `phase8_label_mapping_plan.md` §3 (`raw_record_json` becomes a pointer) and **needs your approval**.
6. **Use Colab for anything that would unpack beyond about 2 GB** (AIT-LDS, and the optional 100M scan). Only filtered Parquet comes back to the Mac.
7. **No script deletes anything.** If a temporary file is unavoidable, it is listed in the storage ledger and removed only with your permission.
8. **Check before and after every step.** Measure free space before (abort if the projected result would fall below 15 GB free) and record before/after sizes in `outputs/phase8/storage_ledger.json`.

## 2. What the sources support

| Mechanism | WitFoo 2M | WitFoo 100M | Evidence |
| :--- | :--- | :--- | :--- |
| **Per-file download** | Yes. Signals, incident leads, metadata and graph are separate files. | Yes. 58 signal shards (13–108 MB each). | HF tree API, 2026-11-01 |
| **Skip the graph** | Yes. Graph is 7.738 GB of the 7.741 GB repo; signals are 0.128 GB. | Yes. 8.45 GB graph vs 4.37 GB signals. | HF tree API |
| **Column projection over HTTP** (read only the needed columns) | Yes (standard Parquet). | Yes | Parquet format; `hf://` filesystem |
| **Row-group skipping** (read only parts of a file) | Possible. How much it helps depends on the row-group layout, which is **unknown until the file footer is read** (a few KB). | Possible | Not yet checked |
| **Streaming** (`datasets` `streaming=True`) | Yes, but it still moves every byte over the network; it only saves disk | Yes | `datasets` library |
| **Server-side row filtering** (HF dataset viewer `/filter`) | Not available today: the 2M repo's viewer service reported "locked" | The statistics endpoint worked on 2026-10-31 | datasets-server responses |
| **Small summary files** | `signals/metadata.json` (10 KB), `build/*.json` (2.9 MB), `reference/lead_rules_catalog.json` (0.15 MB) | Same | HF tree API |

**Avoid locally:**
- `datasets.load_dataset()`: it stores the Parquet in the hub cache **and** writes uncompressed Arrow into `~/.cache/huggingface/datasets`.
- `snapshot_download` without `allow_patterns`: it would fetch the 7.7 GB graph.

## 3. Step-by-step plan with storage estimates

**Estimate key:**
- *Measured* = from file sizes on the Hub or on disk.
- *Estimate* = my projection. It is shown as a range and will be checked after each step.

### Step 0. Summary files only (≈ 3.1 MB, measured)
- **Files:** `signals/metadata.json`, `build/label_stats.json`, `build/subset_stats.json`, `build/verification_report.json`, `build/sanitize_stats.json`, `reference/lead_rules_catalog.json`
- **Why:** exact per-org, per-stream and per-message-type distributions and selection parameters, before any data is fetched. This may settle whether the 100M is worth touching at all.
- **Peak / persistent disk:** 3.1 MB / 3.1 MB.

### Step 1. Overlap check with our 20K (no data file kept)
- **What:** read only `artifact_id`, `timestamp` and `label_binary` from `signals.parquet` (2M) by column projection over HTTP, and join on our 20,000 `event_id`s. If there is no match, repeat for 100M shard `signals-00000.parquet`, whose rows start where ours start.
- **Output:** `outputs/phase8/witfoo_overlap_check.parquet`, with at most 20,000 rows (< 1 MB).
- **Transfer:** *estimate* 10–60 MB over the network. **Disk:** ≈ 0. **RAM:** < 0.5 GB.
- **What it settles:** v1 vs v2 provenance of our 20K, and whether its tokens can be joined to v2 (comparison doc §2).

### Step 2. WitFoo 2M signal tables (127.6 MB, measured)
- **Files:** `signals/signals.parquet` (117.06 MB) and `signals/incident_signals.parquet` (10.52 MB). **The graph (7.74 GB) is not downloaded.**
- **Why not the "complete 2M":** these two files are **1.6%** of the repo and contain every labelled event. The rest is graph and GraphML for provenance-graph research, which we don't need.
- **How:** `hf_hub_download(repo_id="witfoo/precinct6-cybersecurity", repo_type="dataset", filename=..., revision="v2.1.0" commit, local_dir="dataset/external/WITFOO_2M/raw")`, then write `MANIFEST.sha256` and run `chmod a-w`.
- **Check the Xet cache** before and after. If the download also leaves chunk copies in `~/.cache/huggingface/xet` (currently 1.32 GB), report it and ask before clearing.
- **Peak / persistent disk:** ≈ 128 MB, plus up to ≈ 128 MB of Xet chunks (*estimate*) / 128 MB.

### Step 3. Profile (no labelling)
- **What:** pyarrow `iter_batches(batch_size=100_000, columns=[label_binary, stream_name, message_type, org_id, matched_rules, set_roles, attack_tactics, disposition, is_false_positive, event_time])`, plus `message_sanitized` for positive rows only, to count templates.
- **Output:** `phase8b_source_profile.md` and `.json` (< 1 MB).
- **RAM:** *estimate* < 2 GB (wide text column only for positive rows). **Disk:** < 1 MB.
- **Decision point:** if the 106,793 suspicious rows cover enough distinct rules and templates, the 100M is **not needed**.

### Step 4. Normalise the selected WitFoo rows into one Parquet (zstd)
- **Rows:**
  - all positives: 106,793 suspicious + 7,728 live malicious + 238,511 incident leads = **353,032** (measured counts, before dedup and capping);
  - benign capped per template/stream/org (target ≤ 200,000 rows; final number set after profiling).
- **Output:** `outputs/phase8/normalised/WITFOO_2M.parquet`. *Estimate:* **50–150 MB.** The 2M averages about 58 bytes per row compressed; normalised rows add our mapping and group-key columns but use pointers instead of record copies.
- **Peak:** output size plus about 1 batch in RAM.

### Step 5 (conditional, only if Step 3 shows too little positive variety). Extra suspicious rows from the 100M
| Option | How | Local disk peak | Comment |
| :--- | :--- | :--- | :--- |
| **A. Colab (recommended)** | In Colab, download the 58 signal shards (4.37 GB, measured) to the VM disk, filter to `label_binary == 'suspicious'` (615,134 rows) and selected columns, write one zstd Parquet to Drive, then fetch only that file to the Mac | Only the filtered file: *estimate* 40–120 MB | The VM disk is wiped when the session ends, so no clean-up is needed. Check free Drive space first, since the notebook already writes to `MyDrive/SIEM_ASTRA`. |
| B. Local, shard by shard, remote-read | Per shard, project `label_binary` and `artifact_id` over HTTP, then fetch the other columns only for row groups containing suspicious rows; nothing persisted except the filtered output | *estimate* < 200 MB plus output | Slower; network-heavy if positives are spread across many row groups |
| ✗ Full local download | 4.37 GB, plus processing | ≥ 4.4 GB | **Not proposed** |

### Other Tier 1 sources (after WitFoo; each needs its own approval)
| Source | Download (measured) | Processing | Persistent local (estimate) |
| :--- | :--- | :--- | :--- |
| **AIT-ADS** | `ait_ads.zip` 96.2 MB + `labels.csv` 3.7 KB | Read the JSON members **directly from the zip** with Python `zipfile`, with **no extraction** (unpacked size is unknown and JSON is usually 10× or more). Batch-write Parquet. | Zip 96 MB + Parquet ≈ 30–100 MB |
| **CSIC 2010** (once the licence is confirmed) | Official size unknown; the Kaggle mirror is 29.5 MB | Small; pandas is fine | ≈ 30 MB raw + < 10 MB Parquet |
| **AIT-LDS V2** (one testbed) | `russellmitchell.zip` 7.1 GB | **Colab only.** The card puts unpacked testbeds at 14–39 GB, which breaks the local cap. In Colab, stream the needed log files and the labels from the zip and write a Parquet subset to Drive. | Only the subset: *estimate* 0.1–0.5 GB. **The 7.1 GB zip is not kept locally.** |

## 4. Storage budget summary

| Item | Local peak | Local persistent | Basis |
| :--- | :--- | :--- | :--- |
| Current project | – | 0.22 GB | Measured |
| Step 0 summary files | 0.003 GB | 0.003 GB | Measured |
| Step 1 overlap check | ≈ 0 | < 0.001 GB | Estimate |
| Step 2 WitFoo 2M signal tables | 0.26 GB (with possible Xet chunks) | 0.13 GB | Measured / estimate |
| Steps 3–4 profile + normalised WitFoo | 0.15 GB + RAM | 0.05–0.15 GB | Estimate |
| Step 5A optional 100M suspicious (via Colab) | 0.12 GB | 0.04–0.12 GB | Estimate |
| AIT-ADS | 0.2 GB | 0.13–0.2 GB | Measured zip / estimate |
| CSIC 2010 | 0.04 GB | 0.04 GB | Mirror size / estimate |
| AIT-LDS subset (via Colab) | 0.5 GB | 0.1–0.5 GB | Estimate |
| Later: proposed integrated candidate (Parquet) | 0.3 GB | 0.1–0.3 GB | Estimate |
| **Total project after all steps** | | **≈ 0.8–1.7 GB** | Well inside the 20 GB cap |
| **Free space after** | | **≈ 38 GB** | Floor of 15 GB respected |

**What would break the budget:**
- unpacking AIT-LDS locally (≥ 21 GB peak);
- downloading the WitFoo graph directories (7.7–8.5 GB);
- downloading the full 100M signals locally (4.4 GB, inside the cap but unnecessary);
- `load_dataset()` Arrow caches.

All four are excluded from this plan.

## 5. Guardrails built into each script

- **Pre-flight check:** `shutil.disk_usage("/")`; abort if `free − projected_bytes < 15 GB`.
- **Write-once raw files:** `MANIFEST.sha256` is written immediately, then `chmod a-w` on the raw files.
- **Protected-file check:** re-verify the SHA-256 of the master and Phase 7 files (`phase8_integration_plan.md` §1) at the start and end of every step.
- **Storage ledger:** append bytes added per path, plus cache sizes (HF hub, Xet, pip) before and after, to `outputs/phase8/storage_ledger.json`.
- **No `rm`, `unlink` or `shutil.rmtree`** anywhere in the pipeline code.
- **RAM limits:** batch size 100,000 rows; text columns are read only for rows that need them; watch memory with `psutil` and halve the batch size above 6 GB.

## 6. Decisions needed

1. **Steps 0 and 1:** approve the 3.1 MB of summary files and the remote 3-column overlap check (no data file kept)?
2. **Step 2:** approve downloading **only** the two WitFoo 2M signal files (127.6 MB), not the 7.7 GB graph?
3. **Pointer change:** approve replacing `raw_record_json` with a pointer to the kept original (mapping plan §3)?
4. **Budget:** confirm a **20 GB cap** and a **15 GB minimum free** (rather than 30 GB)?
5. **Colab:** OK to use Colab for AIT-LDS and the optional 100M step? How much free space does your Google Drive have? It must hold the filtered outputs (estimate under 1 GB).
6. **Caches:** should I leave the unrelated caches (about 5.8 GB of HF models, Xet and pip) untouched? That is the default. I will not touch them unless you ask.
