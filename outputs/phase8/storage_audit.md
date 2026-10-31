# Phase 8: Storage Audit

**Date:** 2026-11-01
**Mode:** read-only. Nothing was downloaded, deleted, moved or modified.
**Machine data:** `storage_audit.json`. Reproduce with `python scripts/storage_audit_phase8.py`.

## 1. Disk capacity

| Item | Value |
| :--- | :--- |
| Machine | MacBook Air M5, 16 GB RAM, no external storage |
| Internal SSD (APFS container) | 494.4 GB |
| **Free space now** | **39.9 GB** |
| Used | 454.5 GB (92%) |

### Budget recommendation

You asked for a budget of 20–30 GB. With 39.9 GB free:
- **30 GB would leave about 10 GB free.** That is too little for macOS on a 16 GB machine, which needs room for swap during pandas work, system updates and APFS snapshots.
- **Recommended:** a **hard cap of 20 GB** for project growth, and a **floor of 15 GB free space at all times**. Every download or processing step should check free space before it starts and abort if it would cross the floor.
- The plan in `selective_download_plan.md` should need **under 1 GB locally** for the Tier 1 sources. The cap is a safety limit, not a target.

## 2. Current project folder

**Total: 216 MB in 102 files.**

| Path | Size |
| :--- | :--- |
| `outputs/` | 184.5 MB |
| `.git/` (history; every output is committed) | 31.6 MB |
| `scripts/`, `training/`, `dataset/`, `.DS_Store` | < 0.2 MB |

### Largest files

| File | Size | Notes |
| :--- | :--- | :--- |
| `outputs/merged_soc_dataset.jsonl` | 72.1 MB | Master, JSONL copy (**protected**) |
| `outputs/merged_soc_dataset.csv` | 38.7 MB | Master, CSV copy (**protected**) |
| `outputs/dataset1_cleaned.csv` | 32.2 MB | Phase 2 output. Its 100,000 rows are also inside the master. |
| `outputs/merged_soc_dataset.parquet` | 12.9 MB | Master, Parquet copy (**protected**) |
| `outputs/supervised_soc_dataset.jsonl` | 11.8 MB | |
| `outputs/supervised_soc_dataset.csv` | 6.3 MB | Byte-identical to `dataset2_cleaned.csv` |
| `outputs/dataset2_cleaned.csv` | 6.3 MB | Byte-identical to `supervised_soc_dataset.csv` |

**Format efficiency:** the same 120,000 rows take 12.9 MB as Parquet, 38.7 MB as CSV (3×) and 72.1 MB as JSONL (5.6×). This is why every new output in Phase 8 should be **Parquet (zstd) only**.

## 3. Duplicate copies (identified, **not deleted**)

### 3.1 Byte-identical files
| Files | SHA-256 | Size each |
| :--- | :--- | :--- |
| `outputs/dataset2_cleaned.csv` = `outputs/supervised_soc_dataset.csv` | `5ab07295…3149` | 6.3 MB |

### 3.2 Same dataset in several formats
Each copy was checked: same row count and the same set of `event_id`s as the Parquet copy.

| Logical dataset | Canonical | Other copies | Size of other copies |
| :--- | :--- | :--- | :--- |
| Master, 120,000 rows | `merged_soc_dataset.parquet` | `.csv`, `.jsonl` | 110.8 MB (**protected; keep**) |
| Supervised, 20,000 rows | `supervised_soc_dataset.parquet` | `.csv`, `.jsonl`, `dataset2_cleaned.csv` | 24.4 MB |
| Deduplicated, 4,304 rows | `merged_soc_dataset_deduplicated.parquet` | `.csv` | 1.6 MB |
| Phase 7 balanced, 484 rows | `merged_soc_dataset_balanced.parquet` | `.csv`, `.jsonl` | 0.5 MB (**protected; keep**) |
| Dataset 1, 100,000 rows | Contained in the master | `dataset1_cleaned.csv` | 32.2 MB |

### 3.3 Copies outside the project folder
| Item | Finding |
| :--- | :--- |
| `~/Downloads/SIEM_Qwen3_4B_finetune.ipynb` | Byte-identical to `training/SIEM_Qwen3_4B_finetune.ipynb` (36 KB) |
| `~/Desktop/Ultimate Project/AXI/SIEM_Trainer/` (1.5 MB) | A separate, related folder (lab scripts, `access.log`, `dataset.json`). Not inspected further and not part of this audit's scope. |
| Git history | `.git` keeps a compressed copy of every committed output (31.6 MB) |

### 3.4 What could be reclaimed (only with your permission)
- **Inside the project:** at most about **58 MB** of non-protected alternate copies (supervised CSV/JSONL, `dataset2_cleaned.csv`, `dataset1_cleaned.csv`, deduplicated CSV).
- **This is not worth doing for space.** It is 0.15% of free disk, and some phases or the Colab notebook may read those formats.
- **Recommendation:** keep everything as it is. The real storage risk is new downloads and caches (§4–5), not the existing project.

## 4. Temporary files and caches (identified, **not deleted**)

| Item | Location | Size | Notes |
| :--- | :--- | :--- | :--- |
| `.DS_Store` | Project root | 6 KB | macOS Finder metadata |
| Python virtual env (created by me in Phase 8 for pandas) | `/private/tmp/claude-501/…/scratchpad/venv` | 256 MB | Session scratch space; macOS clears `/private/tmp` on reboot. Needed because the system pandas is broken (numpy ABI mismatch). |
| Hugging Face hub cache | `~/.cache/huggingface/hub` | 3.54 GB | **Unrelated** models: BLIP captioning (2.9 GB), ViT (338 MB), EfficientNet-B4 (76 MB), faster-whisper (2.5 MB) |
| Hugging Face Xet chunk cache | `~/.cache/huggingface/xet` | 1.32 GB | Grows with Hub downloads |
| Hugging Face `datasets` cache | `~/.cache/huggingface/datasets` | 0 GB | Does not exist yet. **`load_dataset()` would write uncompressed Arrow files here.** |
| pip cache | `~/Library/Caches/pip` | 0.99 GB | |
| Phase 2 source file | `/tmp/soc_merged_sample.parquet` | **missing** | The raw file Phase 2 read is gone, and `dataset/dataset1.txt` and `dataset/dataset2.txt` are 0 bytes. The 120k master is now the earliest copy of the data. |

**About 5.8 GB of caches unrelated to the project** (HF models, Xet, pip) could be freed **if you choose to**. I have not touched them.

## 5. Storage risks for the next phase

1. **`datasets.load_dataset()` doubles or triples storage.** It downloads Parquet into the hub cache *and* converts it to uncompressed Arrow in `~/.cache/huggingface/datasets`. **Do not use it locally.** Download single files with `hf_hub_download(..., local_dir=...)`, or read Parquet directly with pyarrow.
2. **The Xet chunk cache grows silently** on every Hub download. Measure it before and after each download, and cap or clear it through the setting your installed `huggingface_hub` supports (check that version's docs).
3. **Zip extraction (AIT datasets).** The AIT-LDS V2 card says each testbed unpacks to **14–39 GB**. Extracting even the smallest testbed locally (7.1 GB zip plus at least 14 GB unpacked) would break the 20 GB cap. Read the zip members directly, or process in Colab (see the plan).
4. **CSV/JSONL exports** are 3–6× the size of Parquet. Export only on request.
5. **RAM (16 GB).** Loading 2M wide rows into pandas at once could use several GB (estimate). Use pyarrow `iter_batches` with column projection.
