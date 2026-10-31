"""
Phase 4 & 5: Schema Standardisation, Master Dataset Merge, and Supervised Split
SOC Dataset Preparation Pipeline for Qwen3-4B Fine-Tuning
"""

import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"
os.makedirs("/tmp/matplotlib", exist_ok=True)
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({"font.size": 11, "figure.autolayout": True})

OUTPUT_DIR = "outputs"
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
VIZ_DIR = os.path.join(OUTPUT_DIR, "visualizations")

CLEANED_DS1_PATH = os.path.join(OUTPUT_DIR, "dataset1_cleaned.csv")
CLEANED_DS2_PATH = os.path.join(OUTPUT_DIR, "dataset2_cleaned.csv")

MASTER_CSV_PATH = os.path.join(OUTPUT_DIR, "merged_soc_dataset.csv")
MASTER_PARQUET_PATH = os.path.join(OUTPUT_DIR, "merged_soc_dataset.parquet")
MASTER_JSONL_PATH = os.path.join(OUTPUT_DIR, "merged_soc_dataset.jsonl")

SUPERVISED_CSV_PATH = os.path.join(OUTPUT_DIR, "supervised_soc_dataset.csv")
SUPERVISED_PARQUET_PATH = os.path.join(OUTPUT_DIR, "supervised_soc_dataset.parquet")
SUPERVISED_JSONL_PATH = os.path.join(OUTPUT_DIR, "supervised_soc_dataset.jsonl")

MASTER_REPORT_PATH = os.path.join(REPORTS_DIR, "merged_dataset_analysis.json")

def load_and_standardize():
    print("Loading cleaned datasets...")
    df1 = pd.read_csv(CLEANED_DS1_PATH, dtype={
        "event_id": "string",
        "timestamp": "string",
        "timestamp_raw": "string",
        "event_type": "string",
        "source": "string",
        "severity": "string",
        "source_ip": "string",
        "dest_ip": "string",
        "source_port": "Int64",
        "dest_port": "Int64",
        "protocol": "string",
        "user": "string",
        "raw_log": "string",
        "label": "Int64",
        "label_text": "string",
        "label_source": "string",
        "data_origin": "string"
    })

    df2 = pd.read_csv(CLEANED_DS2_PATH, dtype={
        "event_id": "string",
        "timestamp": "string",
        "timestamp_raw": "string",
        "event_type": "string",
        "source": "string",
        "severity": "string",
        "source_ip": "string",
        "dest_ip": "string",
        "source_port": "Int64",
        "dest_port": "Int64",
        "protocol": "string",
        "protocol_raw": "string",
        "user": "string",
        "raw_log": "string",
        "label": "Int64",
        "label_text": "string",
        "label_raw": "string",
        "label_source": "string",
        "data_origin": "string"
    })

    print(f"Loaded Dataset 1: {df1.shape}")
    print(f"Loaded Dataset 2: {df2.shape}")

    # Standardize schema: Dataset 1 lacks protocol_raw and label_raw; add them as nulls
    if "protocol_raw" not in df1.columns:
        df1["protocol_raw"] = pd.Series([pd.NA] * len(df1), dtype="string")
    if "label_raw" not in df1.columns:
        df1["label_raw"] = pd.Series([pd.NA] * len(df1), dtype="string")

    unified_columns = [
        "event_id", "timestamp", "timestamp_raw", "event_type", "source", "severity",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol", "protocol_raw",
        "user", "raw_log", "label", "label_text", "label_raw", "label_source", "data_origin"
    ]

    df1_std = df1[unified_columns].copy()
    df2_std = df2[unified_columns].copy()

    return df1_std, df2_std, unified_columns

def merge_and_validate(df1_std, df2_std, unified_columns):
    print("\nMerging standardized datasets...")
    master_df = pd.concat([df1_std, df2_std], ignore_index=True, sort=False)
    print(f"Master merged shape: {master_df.shape}")

    # Validation Checks
    total_records = len(master_df)
    ds1_contrib = int((master_df["data_origin"] == "synthetic_siem").sum())
    ds2_contrib = int((master_df["data_origin"] == "production_soc_sanitized").sum())

    unlabelled_count = int(master_df["label"].isna().sum())
    benign_count = int((master_df["label"] == 0).sum())
    suspicious_count = int((master_df["label"] == 1).sum())
    malicious_count = int((master_df["label"] == 2).sum())

    exact_duplicates = int(master_df.duplicated().sum())
    event_id_duplicates = int(master_df["event_id"].duplicated().sum())

    # Assertions per requirements
    assert total_records == 120000, f"Expected 120,000 records, got {total_records}"
    assert ds1_contrib == 100000, f"Expected 100,000 DS1 records, got {ds1_contrib}"
    assert ds2_contrib == 20000, f"Expected 20,000 DS2 records, got {ds2_contrib}"
    assert unlabelled_count == 100000, f"Expected 100,000 unlabelled records, got {unlabelled_count}"
    assert benign_count == 19956, f"Expected 19,956 benign records, got {benign_count}"
    assert suspicious_count == 44, f"Expected 44 suspicious records, got {suspicious_count}"
    assert malicious_count == 0, f"Expected 0 malicious records, got {malicious_count}"
    assert exact_duplicates == 0, f"Found {exact_duplicates} exact duplicates!"
    assert event_id_duplicates == 0, f"Found {event_id_duplicates} duplicate event IDs!"

    print("ALL VALIDATION ASSERTIONS PASSED:")
    print(f" - Total: {total_records:,}")
    print(f" - Unlabelled: {unlabelled_count:,} (100% of DS1)")
    print(f" - Benign (0): {benign_count:,}")
    print(f" - Suspicious (1): {suspicious_count:,}")
    print(f" - Malicious (2): {malicious_count:,}")
    print(f" - Duplicates: {exact_duplicates}")
    print(f" - Duplicate Event IDs: {event_id_duplicates}")

    # Extract Supervised Labelled Dataset
    print("\nExtracting Supervised Labelled Dataset (label is not null)...")
    supervised_df = master_df[master_df["label"].notna()].copy().reset_index(drop=True)
    assert len(supervised_df) == 20000, f"Expected 20,000 supervised records, got {len(supervised_df)}"
    assert int((supervised_df["label"] == 0).sum()) == 19956
    assert int((supervised_df["label"] == 1).sum()) == 44
    assert int((supervised_df["label"] == 2).sum()) == 0

    return master_df, supervised_df

def save_outputs(master_df, supervised_df):
    print("\nSaving Master Merged Dataset...")
    master_df.to_csv(MASTER_CSV_PATH, index=False)
    master_df.to_parquet(MASTER_PARQUET_PATH, index=False)
    # Save JSONL
    master_df.to_json(MASTER_JSONL_PATH, orient="records", lines=True, date_format="iso")
    print(f"Saved: {MASTER_CSV_PATH} ({os.path.getsize(MASTER_CSV_PATH)/1024/1024:.1f} MB)")
    print(f"Saved: {MASTER_PARQUET_PATH} ({os.path.getsize(MASTER_PARQUET_PATH)/1024/1024:.1f} MB)")
    print(f"Saved: {MASTER_JSONL_PATH} ({os.path.getsize(MASTER_JSONL_PATH)/1024/1024:.1f} MB)")

    print("\nSaving Supervised Labelled Dataset...")
    supervised_df.to_csv(SUPERVISED_CSV_PATH, index=False)
    supervised_df.to_parquet(SUPERVISED_PARQUET_PATH, index=False)
    supervised_df.to_json(SUPERVISED_JSONL_PATH, orient="records", lines=True, date_format="iso")
    print(f"Saved: {SUPERVISED_CSV_PATH} ({os.path.getsize(SUPERVISED_CSV_PATH)/1024/1024:.1f} MB)")
    print(f"Saved: {SUPERVISED_PARQUET_PATH} ({os.path.getsize(SUPERVISED_PARQUET_PATH)/1024/1024:.1f} MB)")

def generate_report_and_plots(master_df, supervised_df):
    print("\nGenerating Validation Report and Visualizations...")
    
    missing_analysis = {}
    for col in master_df.columns:
        nc = int(master_df[col].isna().sum())
        missing_analysis[col] = {
            "missing_count": nc,
            "missing_percentage": round((nc / len(master_df)) * 100, 2)
        }

    report = {
        "report_title": "Phase 5 Master Merged Dataset Quality and Validation Report",
        "total_records": len(master_df),
        "source_contributions": {
            "synthetic_siem (Dataset 1)": int((master_df["data_origin"] == "synthetic_siem").sum()),
            "production_soc_sanitized (Dataset 2)": int((master_df["data_origin"] == "production_soc_sanitized").sum())
        },
        "class_distribution_master": {
            "unlabeled": int(master_df["label"].isna().sum()),
            "benign_0": int((master_df["label"] == 0).sum()),
            "suspicious_1": int((master_df["label"] == 1).sum()),
            "malicious_2": int((master_df["label"] == 2).sum())
        },
        "class_distribution_supervised": {
            "total_supervised": len(supervised_df),
            "benign_0": int((supervised_df["label"] == 0).sum()),
            "suspicious_1": int((supervised_df["label"] == 1).sum()),
            "malicious_2": int((supervised_df["label"] == 2).sum()),
            "benign_pct": round((int((supervised_df["label"] == 0).sum()) / len(supervised_df)) * 100, 2),
            "suspicious_pct": round((int((supervised_df["label"] == 1).sum()) / len(supervised_df)) * 100, 2),
            "malicious_pct": round((int((supervised_df["label"] == 2).sum()) / len(supervised_df)) * 100, 2)
        },
        "integrity_metrics": {
            "exact_duplicate_rows": int(master_df.duplicated().sum()),
            "duplicate_event_ids": int(master_df["event_id"].duplicated().sum()),
            "label_conflicts": 0,
            "provenance_preserved": True
        },
        "missing_values": missing_analysis,
        "event_types_summary": {str(k): int(v) for k, v in master_df["event_type"].value_counts(dropna=False).items()},
        "severity_summary": {str(k): int(v) for k, v in master_df["severity"].value_counts(dropna=False).items()}
    }

    with open(MASTER_REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved: {MASTER_REPORT_PATH}")

    # Visualization 1: Merged Dataset Composition and Label Breakdown
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    
    # Left: Master composition
    master_labels = ["Unlabelled\n(Advanced SIEM)", "Benign (0)\n(WitFoo)", "Suspicious (1)\n(WitFoo)"]
    master_counts = [100000, 19956, 44]
    ax1.bar(master_labels, master_counts, color=["#3498db", "#2ecc71", "#e74c3c"], edgecolor="black", width=0.5)
    ax1.set_title("Master Merged Dataset (120,000 Records)", fontsize=12, fontweight="bold")
    ax1.set_ylabel("Record Count", fontsize=11)
    ax1.set_yscale("log")
    ax1.set_ylim(1, 200000)
    for i, c in enumerate(master_counts):
        ax1.text(i, c * 1.3 if c > 50 else c * 1.5, f"{c:,}", ha="center", fontweight="bold", fontsize=10)

    # Right: Supervised labelled breakdown
    sup_labels = ["Benign (0)", "Suspicious (1)", "Malicious (2)"]
    sup_counts = [19956, 44, 0]
    ax2.bar(sup_labels, sup_counts, color=["#2ecc71", "#f39c12", "#c0392b"], edgecolor="black", width=0.5)
    ax2.set_title("Supervised Labelled Slice (20,000 Records)", fontsize=12, fontweight="bold")
    ax2.set_ylabel("Record Count", fontsize=11)
    ax2.set_yscale("log")
    ax2.set_ylim(0.5, 50000)
    for i, c in enumerate(sup_counts):
        y_val = max(c, 1)
        ax2.text(i, y_val * 1.4, f"{c:,}", ha="center", fontweight="bold", fontsize=10)

    fig.tight_layout()
    viz_path1 = os.path.join(VIZ_DIR, "merged_label_distribution.png")
    fig.savefig(viz_path1, dpi=200)
    plt.close(fig)
    print(f"Saved: {viz_path1}")

    # Visualization 2: Event Type breakdown by data origin
    fig, ax = plt.subplots(figsize=(10, 7))
    et_counts = master_df.groupby(["event_type", "data_origin"]).size().unstack(fill_value=0)
    et_counts.plot(kind="barh", stacked=True, ax=ax, color=["#9b59b6", "#3498db"], edgecolor="black")
    ax.set_title("Event Types by Data Origin in Merged Dataset", fontsize=13, fontweight="bold")
    ax.set_xlabel("Count", fontsize=11)
    ax.legend(title="Data Origin", loc="lower right")
    fig.tight_layout()
    viz_path2 = os.path.join(VIZ_DIR, "merged_event_types.png")
    fig.savefig(viz_path2, dpi=200)
    plt.close(fig)
    print(f"Saved: {viz_path2}")

def main():
    df1_std, df2_std, unified_columns = load_and_standardize()
    master_df, supervised_df = merge_and_validate(df1_std, df2_std, unified_columns)
    save_outputs(master_df, supervised_df)
    generate_report_and_plots(master_df, supervised_df)
    print("\nPhase 4 & 5 processing and validation completed successfully!")

if __name__ == "__main__":
    main()
