"""
Phase 8: Read-only storage audit (disk space, project sizes, duplicate copies, temp files)
SOC Dataset Preparation Pipeline for Qwen3-4B Fine-Tuning

Writes outputs/phase8/storage_audit.json. Never deletes, moves or modifies any file.
"""

import os
import json
import shutil
import hashlib
import datetime
from collections import defaultdict

import pandas as pd

PROJECT_DIR = "."
OUT_JSON = os.path.join("outputs", "phase8", "storage_audit.json")

BUDGET_GB = {"target_cap": 20, "user_upper_bound": 30, "min_free_space_floor": 15}

# Same logical dataset stored in several formats (checked by row count + event_id set below)
FORMAT_GROUPS = {
    "master_120k": ["outputs/merged_soc_dataset.parquet", "outputs/merged_soc_dataset.csv", "outputs/merged_soc_dataset.jsonl"],
    "supervised_20k": ["outputs/supervised_soc_dataset.parquet", "outputs/supervised_soc_dataset.csv",
                       "outputs/supervised_soc_dataset.jsonl", "outputs/dataset2_cleaned.csv"],
    "deduplicated_4304": ["outputs/merged_soc_dataset_deduplicated.parquet", "outputs/merged_soc_dataset_deduplicated.csv"],
    "phase7_balanced_484": ["outputs/merged_soc_dataset_balanced.parquet", "outputs/merged_soc_dataset_balanced.csv",
                            "outputs/merged_soc_dataset_balanced.jsonl"],
}
PROTECTED = {"outputs/merged_soc_dataset.parquet", "outputs/merged_soc_dataset.csv", "outputs/merged_soc_dataset.jsonl",
             "outputs/merged_soc_dataset_balanced.parquet", "outputs/merged_soc_dataset_balanced.csv",
             "outputs/merged_soc_dataset_balanced.jsonl"}

# Caches outside the project that live on the same internal SSD
EXTERNAL_PATHS = {
    "huggingface_cache": os.path.expanduser("~/.cache/huggingface"),
    "huggingface_hub_cache": os.path.expanduser("~/.cache/huggingface/hub"),
    "huggingface_xet_cache": os.path.expanduser("~/.cache/huggingface/xet"),
    "huggingface_datasets_cache": os.path.expanduser("~/.cache/huggingface/datasets"),
    "pip_cache": os.path.expanduser("~/Library/Caches/pip"),
}

# Remote sizes from the Hugging Face tree API (metadata only, nothing downloaded), retrieved 2026-11-01
WITFOO_REMOTE = {
    "retrieved": "2026-11-01",
    "api": "https://huggingface.co/api/datasets/<repo>/tree/main/<dir>?recursive=true",
    "witfoo/precinct6-cybersecurity (2M, v2.1.0)": {
        "signals/signals.parquet": 117056748,
        "signals/incident_signals.parquet": 10518589,
        "signals/metadata.json": 10098,
        "build/ (4 json files)": 2900000,
        "reference/lead_rules_catalog.json": 150000,
        "graph/ (983 files)": 7738300000,
        "total_repo_bytes": 7741000000,
    },
    "witfoo/precinct6-cybersecurity-100m (v2.1.0)": {
        "signals/ (58 signal shards + incident_signals + metadata)": 4365600000,
        "largest_signal_shard signals-00000.parquet": 107830000,
        "smallest_signal_shard signals-00057.parquet": 13320000,
        "build/ (3 json files)": 2800000,
        "reference/lead_rules_catalog.json": 150000,
        "graph/ (983 files)": 8452700000,
        "total_repo_bytes": 8455000000,
    },
}


def dir_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            if not os.path.islink(fp):
                total += os.path.getsize(fp)
    return total


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_ids(path):
    if path.endswith(".parquet"):
        return pd.read_parquet(path, columns=["event_id"])["event_id"].astype(str)
    if path.endswith(".csv"):
        return pd.read_csv(path, usecols=["event_id"], dtype=str)["event_id"]
    return pd.read_json(path, lines=True, dtype=False)["event_id"].astype(str)


def mb(n):
    return round(n / 1e6, 2)


def main():
    usage = shutil.disk_usage("/")
    files = []
    for root, dirs, fs in os.walk(PROJECT_DIR):
        for f in fs:
            fp = os.path.normpath(os.path.join(root, f))
            files.append((fp, os.path.getsize(fp)))

    by_hash = defaultdict(list)
    for fp, size in files:
        if not fp.startswith(".git" + os.sep) and size > 0:
            by_hash[sha256(fp)].append(fp)
    identical = [{"sha256": h, "files": sorted(p), "bytes_each": os.path.getsize(p[0])}
                 for h, p in by_hash.items() if len(p) > 1]

    groups = {}
    for name, paths in FORMAT_GROUPS.items():
        ids = {p: read_ids(p) for p in paths}
        ref = set(ids[paths[0]])
        groups[name] = {
            "canonical": paths[0],
            "files": {p: {"bytes": os.path.getsize(p), "rows": len(ids[p]), "same_event_ids_as_canonical": set(ids[p]) == ref,
                          "protected": p in PROTECTED} for p in paths},
            "bytes_in_non_canonical_copies": sum(os.path.getsize(p) for p in paths[1:]),
        }

    temp = [fp for fp, _ in files if os.path.basename(fp) in {".DS_Store"} or fp.endswith((".tmp", "~"))
            or "__pycache__" in fp or ".ipynb_checkpoints" in fp]

    top = {}
    for entry in sorted(os.listdir(PROJECT_DIR)):
        p = os.path.join(PROJECT_DIR, entry)
        top[entry] = dir_size(p) if os.path.isdir(p) else os.path.getsize(p)

    report = {
        "report_title": "Phase 8 Storage Audit (read-only)",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "disk": {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
                 "free_gb": round(usage.free / 1e9, 2), "total_gb": round(usage.total / 1e9, 2)},
        "ram_gb": 16,
        "budget_gb": BUDGET_GB,
        "project": {
            "path": os.path.abspath(PROJECT_DIR),
            "total_bytes": sum(s for _, s in files),
            "total_mb": mb(sum(s for _, s in files)),
            "file_count": len(files),
            "top_level_bytes": top,
            "outputs_files_mb": {fp: mb(s) for fp, s in sorted(files, key=lambda x: -x[1])
                                 if fp.startswith("outputs") and s > 100_000},
        },
        "duplicates": {
            "byte_identical_files": identical,
            "same_dataset_multiple_formats": groups,
            "git_history_note": "All outputs are committed, so .git holds a compressed copy of each (pack size in top_level_bytes['.git']).",
        },
        "temporary_files_in_project": temp,
        "external_on_same_disk": {k: {"path": v, "bytes": dir_size(v) if os.path.isdir(v) else 0} for k, v in EXTERNAL_PATHS.items()},
        "witfoo_remote_file_sizes": WITFOO_REMOTE,
        "nothing_deleted_or_modified": True,
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved: {OUT_JSON}")


if __name__ == "__main__":
    main()
