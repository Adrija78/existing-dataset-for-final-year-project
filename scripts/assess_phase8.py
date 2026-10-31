"""
Phase 8: Read-only assessment of the existing labelled data (diversity, templates, shortcuts)
SOC Dataset Preparation Pipeline for Qwen3-4B Fine-Tuning

Reads the Phase 5-7 outputs and writes one JSON report. Never modifies any dataset file.
"""

import os
import re
import json
import hashlib
import pandas as pd

OUTPUT_DIR = "outputs"
PHASE8_DIR = os.path.join(OUTPUT_DIR, "phase8")
REPORT_JSON = os.path.join(PHASE8_DIR, "phase8_existing_data_assessment.json")

MASTER_PARQUET = os.path.join(OUTPUT_DIR, "merged_soc_dataset.parquet")
SUPERVISED_PARQUET = os.path.join(OUTPUT_DIR, "supervised_soc_dataset.parquet")
BALANCED_PARQUET = os.path.join(OUTPUT_DIR, "merged_soc_dataset_balanced.parquet")

PROTECTED_FILES = [
    "merged_soc_dataset.csv", "merged_soc_dataset.parquet", "merged_soc_dataset.jsonl",
    "supervised_soc_dataset.csv", "supervised_soc_dataset.parquet", "supervised_soc_dataset.jsonl",
    "merged_soc_dataset_deduplicated.csv", "merged_soc_dataset_deduplicated.parquet",
    "merged_soc_dataset_balanced.csv", "merged_soc_dataset_balanced.parquet", "merged_soc_dataset_balanced.jsonl",
]

# Phase 7 dedup key, reused so the numbers are comparable
FEAT_COLS = [
    "event_type", "source", "severity", "source_ip", "dest_ip",
    "source_port", "dest_port", "protocol", "user", "raw_log"
]

# Model-input fields used by training/SIEM_Qwen3_4B_finetune.ipynb (cell 2); log_source is excluded
# from its "no usable fields" check (FEATURES[1:]).
NOTEBOOK_FEATURES_CHECKED = ["dest_port", "method", "url", "status_code", "bytes", "user", "auth_method", "user_agent"]

SECURITY_KEYWORDS = r"(?i)fail|invalid|denied|refused|attack|malic|exploit|brute|unauthori|blocked|threat|virus|intrusion|scan|reject|suspect"


def template(raw):
    """Mask variable tokens so that log lines differing only in values collapse to one template."""
    if raw is None or pd.isna(raw):
        return None
    t = raw.replace("\x00", "")
    t = re.sub(r"^<\d+>", "<PRI>", t)
    t = re.sub(r"[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d", "<TS>", t)
    t = re.sub(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?Z?", "<TS>", t)
    t = re.sub(r"HOST-\d+", "<HOST>", t)
    t = re.sub(r"USER-\d+", "<USER>", t)
    t = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<IP>", t)
    t = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<UUID>", t)
    t = re.sub(r"\b0x[0-9a-fA-F]+\b", "<HEX>", t)
    t = re.sub(r"\d+", "<N>", t)
    return re.sub(r"\s+", " ", t).strip()


def host_of(raw):
    if raw is None or pd.isna(raw):
        return None
    m = re.search(r"HOST-\d+", raw)
    return m.group(0) if m else None


def counts(series):
    return {str(k): int(v) for k, v in series.value_counts(dropna=False).items()}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def assess_suspicious(susp):
    susp = susp.copy()
    susp["template"] = susp["raw_log"].map(template)
    susp["host"] = susp["raw_log"].map(host_of)
    counters = susp["raw_log"].str.extract(r"Duration: (\S+) Count: (\d+)")
    susp["counter"] = pd.to_numeric(counters[1])
    per_host = susp.groupby("host")["counter"].agg(["min", "max", "count"])
    return {
        "rows": len(susp),
        "unique_event_ids": int(susp["event_id"].nunique()),
        "unique_raw_logs": int(susp["raw_log"].nunique()),
        "unique_templates": int(susp["template"].nunique()),
        "templates": counts(susp["template"]),
        "by_host": counts(susp["host"]),
        "by_event_type": counts(susp["event_type"]),
        "by_source": counts(susp["source"]),
        "by_severity": counts(susp["severity"]),
        "by_attack_category": {"none recorded in source; only 'auth_failure' event_type": len(susp)},
        "null_counts": {c: int(susp[c].isna().sum()) for c in ["user", "source_ip", "dest_ip", "source_port", "dest_port", "protocol"]},
        "timestamp_min": susp["timestamp"].min(),
        "timestamp_max": susp["timestamp"].max(),
        "rows_with_trailing_nul": int(susp["raw_log"].str.contains("\x00").sum()),
        "counter_ranges_per_host": {
            h: {"min": int(r["min"]), "max": int(r["max"]), "rows": int(r["count"]),
                "values_spanned": int(r["max"] - r["min"] + 1)}
            for h, r in per_host.iterrows()
        },
    }


def assess_benign(ben):
    ben = ben.copy()
    ben["template"] = ben["raw_log"].map(template)
    ben["host"] = ben["raw_log"].map(host_of)
    kw = ben[ben["raw_log"].fillna("").str.contains(SECURITY_KEYWORDS)]
    return {
        "rows": len(ben),
        "unique_by_phase7_feature_key": int(len(ben.drop_duplicates(subset=FEAT_COLS))),
        "unique_raw_logs_non_null": int(ben["raw_log"].nunique()),
        "rows_with_null_raw_log": int(ben["raw_log"].isna().sum()),
        "unique_templates_non_null": int(ben["template"].nunique()),
        "null_raw_log_unique_flow_tuples": int(len(ben[ben["raw_log"].isna()].drop_duplicates(
            subset=["source_ip", "dest_ip", "source_port", "dest_port", "protocol"]))),
        "by_host": counts(ben["host"]),
        "by_source": counts(ben["source"]),
        "by_event_type": counts(ben["event_type"]),
        "top_templates": {k: int(v) for k, v in ben["template"].value_counts().head(25).items()},
        "security_keyword_rows": int(len(kw)),
        "security_keyword_templates": int(kw["template"].nunique()),
        "security_keyword_rows_by_source": counts(kw["source"]),
        "security_relevant_benign_examples": {
            "suspect_long_flow_stealthwatch": int((ben["event_type"] == "suspect long flow").sum()),
            "symantec_ips_submission": int(ben["raw_log"].fillna("").str.contains("Intrusion prevention submission").sum()),
            "critical_severity_rows": int((ben["severity"] == "critical").sum()),
        },
    }


def cross_label_checks(sup):
    sup = sup.copy()
    sup["template"] = sup["raw_log"].map(template)
    sup["host"] = sup["raw_log"].map(host_of)
    # Template family shared by the suspicious rows: "local1: Host: <HOST> Duration: .. Count: ..; <LEVEL>: <msg>"
    family = sup["raw_log"].fillna("").str.contains(r"local1: Host: HOST-\d+ Duration:")
    fam = sup[family]
    fam_rows = [
        {"label": int(r.label), "pri": re.match(r"^<(\d+)>", r.raw_log).group(1), "host": r.host,
         "message": r.raw_log.split(";", 1)[1].strip().rstrip("\x00")}
        for r in fam.itertuples()
    ]
    fam_summary = pd.DataFrame(fam_rows).value_counts().reset_index(name="rows").to_dict("records")

    tmpl_labels = sup.dropna(subset=["template"]).groupby("template")["label"].nunique()
    raw_labels = sup.dropna(subset=["raw_log"]).groupby("raw_log")["label"].nunique()
    susp_hosts = set(sup.loc[sup["label"] == 1, "host"].dropna())

    # Rows the fine-tuning notebook would discard as having no usable model-input field
    present = [c for c in NOTEBOOK_FEATURES_CHECKED if c in sup.columns]
    empty = sup[present].isna().all(axis=1)

    return {
        "templates_with_conflicting_labels": int((tmpl_labels > 1).sum()),
        "raw_logs_with_conflicting_labels": int((raw_labels > 1).sum()),
        "event_ids_duplicated": int(sup["event_id"].duplicated().sum()),
        "host_local1_device_status_family": fam_summary,
        "benign_rows_on_suspicious_hosts": int(((sup["label"] == 0) & sup["host"].isin(susp_hosts)).sum()),
        "notebook_schema_check": {
            "notebook_feature_columns_present_in_dataset": present,
            "notebook_feature_columns_missing_from_dataset": [c for c in NOTEBOOK_FEATURES_CHECKED if c not in sup.columns],
            "rows_with_all_checked_features_null_by_label": {str(k): int(v) for k, v in sup[empty]["label"].value_counts().items()},
            "note": "source is not aliased to log_source in the notebook ALIASES, so log_source would also be 'none'.",
        },
    }


def assess_balanced(bal):
    ben = bal[bal["label"] == 0]
    return {
        "rows": len(bal),
        "by_label": counts(bal["label"]),
        "benign_with_null_raw_log": int(ben["raw_log"].isna().sum()),
        "benign_by_event_type": counts(ben["event_type"]),
    }


def assess_dataset1(master):
    d1 = master[master["data_origin"] == "synthetic_siem"]
    return {
        "rows": len(d1),
        "unique_raw_logs": int(d1["raw_log"].nunique()),
        "timestamp_min": d1["timestamp"].min(),
        "timestamp_max": d1["timestamp"].max(),
        "label_non_null": int(d1["label"].notna().sum()),
        "provenance_note": "darkknight25/Advanced_SIEM_Dataset (Hugging Face); its card describes the data as synthetic.",
    }


def main():
    os.makedirs(PHASE8_DIR, exist_ok=True)
    checksums_before = {f: sha256(os.path.join(OUTPUT_DIR, f)) for f in PROTECTED_FILES}

    master = pd.read_parquet(MASTER_PARQUET)
    sup = pd.read_parquet(SUPERVISED_PARQUET)
    bal = pd.read_parquet(BALANCED_PARQUET)

    report = {
        "report_title": "Phase 8 Existing Labelled Data Assessment (read-only)",
        "master_rows": len(master),
        "supervised_rows": len(sup),
        "supervised_label_counts": counts(sup["label"]),
        "suspicious": assess_suspicious(sup[sup["label"] == 1]),
        "benign": assess_benign(sup[sup["label"] == 0]),
        "cross_label": cross_label_checks(sup),
        "phase7_balanced": assess_balanced(bal),
        "dataset1_unlabelled": assess_dataset1(master),
        "supervised_timestamp_range": [sup["timestamp"].min(), sup["timestamp"].max()],
        "raw_log_month_tokens": counts(sup["raw_log"].dropna().str.extract(r"^(?:<\d+>)?([A-Z][a-z]{2}) +\d")[0]),
    }

    checksums_after = {f: sha256(os.path.join(OUTPUT_DIR, f)) for f in PROTECTED_FILES}
    assert checksums_before == checksums_after, "A protected dataset file changed during assessment"
    report["protected_file_sha256"] = checksums_after

    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Saved: {REPORT_JSON}")


if __name__ == "__main__":
    main()
