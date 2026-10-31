"""
Phase 7: Deduplication, 10:1 Ratio-Capped Balancing, and Leakage Prevention Script
SOC Dataset Preparation Pipeline for Qwen3-4B Fine-Tuning
"""

import os
import json
import re
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

SUPERVISED_PARQUET = os.path.join(OUTPUT_DIR, "supervised_soc_dataset.parquet")

DEDUP_CSV = os.path.join(OUTPUT_DIR, "merged_soc_dataset_deduplicated.csv")
DEDUP_PARQUET = os.path.join(OUTPUT_DIR, "merged_soc_dataset_deduplicated.parquet")

BALANCED_CSV = os.path.join(OUTPUT_DIR, "merged_soc_dataset_balanced.csv")
BALANCED_PARQUET = os.path.join(OUTPUT_DIR, "merged_soc_dataset_balanced.parquet")
BALANCED_JSONL = os.path.join(OUTPUT_DIR, "merged_soc_dataset_balanced.jsonl")

REPORT_JSON = os.path.join(REPORTS_DIR, "phase7_balancing_report.json")
REPORT_MD = os.path.join(REPORTS_DIR, "phase7_balancing_report.md")

RANDOM_SEED = 42
TARGET_RATIO = 10  # 10:1 benign to suspicious ratio

def execute_phase7():
    print("Loading supervised labelled dataset...")
    df = pd.read_parquet(SUPERVISED_PARQUET)
    print(f"Loaded supervised dataset: {df.shape}")

    benign_raw = df[df["label"] == 0].copy().reset_index(drop=True)
    susp_raw = df[df["label"] == 1].copy().reset_index(drop=True)

    print(f"Raw Benign: {len(benign_raw):,}, Raw Suspicious: {len(susp_raw):,}")

    # 1. Deduplication on Benign Records
    # Documented method: exact content match across event_type, source, severity, IPs, ports, protocol, user, raw_log
    feat_cols = [
        "event_type", "source", "severity", "source_ip", "dest_ip",
        "source_port", "dest_port", "protocol", "user", "raw_log"
    ]
    
    is_benign_dup = benign_raw.duplicated(subset=feat_cols, keep="first")
    dup_benign_count = int(is_benign_dup.sum())
    unique_benign = benign_raw[~is_benign_dup].copy().reset_index(drop=True)
    unique_benign_count = len(unique_benign)

    print(f"Benign Duplicates Identified: {dup_benign_count:,}")
    print(f"Unique Benign Records: {unique_benign_count:,}")

    # Suspicious deduplication check
    is_susp_dup = susp_raw.duplicated(subset=feat_cols, keep="first")
    dup_susp_count = int(is_susp_dup.sum())
    unique_susp = susp_raw[~is_susp_dup].copy().reset_index(drop=True)
    unique_susp_count = len(unique_susp)
    print(f"Suspicious Duplicates Identified: {dup_susp_count}")
    print(f"Unique Suspicious Records: {unique_susp_count}")

    # Assemble Deduplicated Dataset (4,260 unique benign + 44 unique suspicious = 4,304 records)
    dedup_df = pd.concat([unique_benign, unique_susp], ignore_index=True, sort=False)
    # Update label_text for binary alert detection
    dedup_df["label_text"] = dedup_df["label"].map({0: "benign", 1: "suspicious/alert"})

    print(f"\nDeduplicated Dataset total rows: {len(dedup_df):,}")

    # 2. 10:1 Stratified Sampling of Unique Benign Records
    n_susp = len(unique_susp)
    n_target_benign = min(n_susp * TARGET_RATIO, unique_benign_count)  # 44 * 10 = 440
    print(f"Target Benign Sample: {n_target_benign} (Ratio: {n_target_benign / n_susp:.1f} : 1)")

    # Stratified proportional sampling by event_type (with min 1 per event type)
    proportions = unique_benign["event_type"].value_counts(normalize=True)
    allocations = (proportions * (n_target_benign - len(proportions))).round().astype(int) + 1
    diff = n_target_benign - allocations.sum()
    allocations.iloc[0] += diff

    sampled_benign_parts = []
    for et, count in allocations.items():
        sub = unique_benign[unique_benign["event_type"] == et]
        sampled_benign_parts.append(sub.sample(n=min(count, len(sub)), random_state=RANDOM_SEED))

    sampled_benign = pd.concat(sampled_benign_parts).reset_index(drop=True)
    assert len(sampled_benign) == n_target_benign, f"Expected {n_target_benign}, got {len(sampled_benign)}"

    # 3. Assemble Balanced Dataset
    # Update label_text to reflect binary alert detection per Instruction 3
    sampled_benign["label_text"] = "benign"
    unique_susp_balanced = unique_susp.copy()
    unique_susp_balanced["label_text"] = "suspicious/alert"

    balanced_df = pd.concat([sampled_benign, unique_susp_balanced], ignore_index=True, sort=False)
    print(f"Balanced Dataset total rows: {len(balanced_df):,} ({len(sampled_benign)} benign + {len(unique_susp_balanced)} suspicious)")

    # Validation Assertions
    assert len(balanced_df) == 484, f"Expected 484 records, got {len(balanced_df)}"
    assert int((balanced_df["label"] == 0).sum()) == 440
    assert int((balanced_df["label"] == 1).sum()) == 44
    assert int((balanced_df["label"] == 2).sum()) == 0
    assert balanced_df.duplicated(subset=["event_id"]).sum() == 0

    # Save Deduplicated and Balanced Outputs
    print("\nSaving files...")
    dedup_df.to_csv(DEDUP_CSV, index=False)
    dedup_df.to_parquet(DEDUP_PARQUET, index=False)
    print(f"Saved: {DEDUP_CSV} ({len(dedup_df)} rows, {os.path.getsize(DEDUP_CSV)/1024/1024:.2f} MB)")
    print(f"Saved: {DEDUP_PARQUET} ({os.path.getsize(DEDUP_PARQUET)/1024/1024:.2f} MB)")

    balanced_df.to_csv(BALANCED_CSV, index=False)
    balanced_df.to_parquet(BALANCED_PARQUET, index=False)
    balanced_df.to_json(BALANCED_JSONL, orient="records", lines=True, date_format="iso")
    print(f"Saved: {BALANCED_CSV} ({len(balanced_df)} rows, {os.path.getsize(BALANCED_CSV)/1024:.1f} KB)")
    print(f"Saved: {BALANCED_PARQUET} ({os.path.getsize(BALANCED_PARQUET)/1024:.1f} KB)")
    print(f"Saved: {BALANCED_JSONL} ({os.path.getsize(BALANCED_JSONL)/1024:.1f} KB)")

    # Deduplication Exclusions Breakdown
    exclusions_by_type = benign_raw[is_benign_dup]["event_type"].value_counts().to_dict()

    # Generate Reports
    print("\nGenerating Reports & Visualizations...")
    report_dict = {
        "report_title": "Phase 7 Deduplication, Class Balancing, and Experimental Dataset Creation Report",
        "methodology": {
            "deduplication_rule": "Exact content matching across all 10 core event features (event_type, source, severity, source_ip, dest_ip, source_port, dest_port, protocol, user, raw_log), keeping the first occurrence.",
            "balancing_ratio": "10:1 (Benign : Suspicious/Alert)",
            "sampling_method": "Stratified proportional sampling across all 12 benign event types with random_state=42",
            "binary_label_mapping": {
                "0": "benign",
                "1": "suspicious/alert"
            }
        },
        "deduplication_statistics": {
            "initial_benign_records": len(benign_raw),
            "duplicate_benign_removed": dup_benign_count,
            "duplicate_benign_percentage": round((dup_benign_count / len(benign_raw)) * 100, 2),
            "unique_benign_retained": unique_benign_count,
            "exclusions_breakdown_by_event_type": {str(k): int(v) for k, v in exclusions_by_type.items()},
            "suspicious_duplicates_found": dup_susp_count,
            "unique_suspicious_retained": unique_susp_count,
            "deduplicated_dataset_total_rows": len(dedup_df)
        },
        "balanced_dataset_statistics": {
            "total_records": len(balanced_df),
            "benign_count": int((balanced_df["label"] == 0).sum()),
            "suspicious_count": int((balanced_df["label"] == 1).sum()),
            "malicious_count": 0,
            "imbalance_ratio": f"{int((balanced_df['label'] == 0).sum()) / int((balanced_df['label'] == 1).sum()):.1f} : 1",
            "benign_percentage": round(int((balanced_df["label"] == 0).sum()) / len(balanced_df) * 100, 2),
            "suspicious_percentage": round(int((balanced_df["label"] == 1).sum()) / len(balanced_df) * 100, 2),
            "benign_event_types_sampled": {str(k): int(v) for k, v in sampled_benign["event_type"].value_counts().items()},
            "suspicious_event_types": {str(k): int(v) for k, v in unique_susp_balanced["event_type"].value_counts().items()}
        },
        "data_leakage_and_shortcut_mitigation": {
            "deterministic_event_type_leak": "event_type == 'auth_failure' is 100% predictive of class 1. Policy: Preserved in dataset as metadata/evaluation target; must be excluded from model input prompts.",
            "host_shortcut_mitigation": "Suspicious events originate strictly from HOST-0002 (23) and HOST-0006 (21). Policy: Must use host-grouped splitting or hostname masking for future training.",
            "grouped_splitting_requirement": "Splits must be template-aware and host-grouped to test actual generalization rather than token memorization."
        },
        "final_experimental_assessment": {
            "suitability_for_qwen3_4b_fine_tuning": "Conditionally suitable as a proof-of-concept / binary triage baseline only.",
            "core_limitations": [
                "Extremely small sample size (484 records total) for a 4B parameter language model.",
                "Zero variety in the suspicious class: all 44 records represent a single auth_failure syslog template.",
                "Zero examples of confirmed malicious attacks (class 2 is unpopulated in this slice).",
                "High risk of overfitting to the specific syslog duration/counter syntax unless supplemented with upstream events."
            ]
        }
    }

    with open(REPORT_JSON, "w") as f:
        json.dump(report_dict, f, indent=2)
    print(f"Saved: {REPORT_JSON}")

    # Generate Markdown Report
    with open(REPORT_MD, "w") as f:
        f.write("# Phase 7: Class Balancing and Experimental Dataset Creation Report\n\n")
        f.write("## 1. Executive Summary\n\n")
        f.write(f"- **Deduplicated Dataset**: `{len(dedup_df):,}` records (`4,260` unique benign + `44` suspicious)\n")
        f.write(f"- **Balanced Experimental Dataset**: `{len(balanced_df)}` records (`440` benign + `44` suspicious)\n")
        f.write("- **Balancing Ratio**: Exactly `10 : 1` (`90.91%` Benign : `9.09%` Suspicious/Alert)\n")
        f.write("- **Sampling Seed**: `42` (fully reproducible stratified proportional sample)\n\n")

        f.write("## 2. Deduplication Audit & Exclusions\n\n")
        f.write(f"Out of `19,956` raw benign records, `{dup_benign_count:,}` records (`78.65%`) were exact duplicates of recurring background daemon tasks.\n\n")
        f.write("| Excluded Event Type | Duplicate Rows Removed | Reason for Exclusion |\n")
        f.write("| :--- | :--- | :--- |\n")
        for et, cnt in exclusions_by_type.items():
            f.write(f"| `{et}` | {cnt:,} | Recurring background syslog/daemon telemetry with identical content |\n")

        f.write("\n## 3. Class Distribution: Before vs. After\n\n")
        f.write("| Stage | Total Records | Benign (0) | Suspicious (1) | Malicious (2) | Imbalance Ratio |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
        f.write(f"| Raw Supervised | 20,000 | 19,956 (99.78%) | 44 (0.22%) | 0 (0.0%) | 453.54 : 1 |\n")
        f.write(f"| Deduplicated | {len(dedup_df):,} | {unique_benign_count:,} (98.98%) | 44 (1.02%) | 0 (0.0%) | 96.82 : 1 |\n")
        f.write(f"| **10:1 Balanced** | **{len(balanced_df)}** | **{n_target_benign} (90.91%)** | **44 (9.09%)** | **0 (0.0%)** | **10.0 : 1** |\n\n")

        f.write("## 4. Final Assessment on Qwen3-4B Fine-Tuning Suitability\n\n")
        f.write("> [!WARNING]\n")
        f.write("> **Suitability Assessment**: This experimental dataset provides a clean proof-of-concept binary triage baseline, but **cannot support generalized production fine-tuning on its own**.\n")
        f.write("> 1. **Volume**: 484 records is minimal for adapting a 4-billion parameter LLM.\n")
        f.write("> 2. **Homogeneity**: The 44 suspicious records originate from only 2 hosts (`HOST-0002` and `HOST-0006`) with one single template (`Authentication failure`).\n")
        f.write("> 3. **Production Recommendation**: For final project deployment, retrieve confirmed incident IDs from the upstream 114M WitFoo dataset to introduce real multi-vector attacks.\n")
    print(f"Saved: {REPORT_MD}")

    # Generate Visualizations
    # 1. Balanced Label Distribution Plot
    fig, ax = plt.subplots(figsize=(7, 4.5))
    b_counts = [int((balanced_df["label"] == 0).sum()), int((balanced_df["label"] == 1).sum())]
    b_labels = [f"Benign (0)\n{b_counts[0]} records (90.9%)", f"Suspicious/Alert (1)\n{b_counts[1]} records (9.1%)"]
    bars = ax.bar(b_labels, b_counts, color=["#2ecc71", "#e74c3c"], width=0.45, edgecolor="black")
    ax.set_title("Experimental Balanced Dataset (10:1 Ratio — 484 Records)", fontweight="bold", fontsize=12)
    ax.set_ylabel("Record Count", fontsize=11)
    ax.set_ylim(0, 520)
    for bar, count in zip(bars, b_counts):
        ax.text(bar.get_x() + bar.get_width()/2, count + 12, f"{count}", ha="center", fontweight="bold", fontsize=11)
    fig.tight_layout()
    viz1 = os.path.join(VIZ_DIR, "balanced_label_distribution.png")
    fig.savefig(viz1, dpi=200)
    plt.close(fig)
    print(f"Saved: {viz1}")

    # 2. Before vs. After Pipeline Progression Plot
    fig, ax = plt.subplots(figsize=(10, 5))
    stages = ["Raw Supervised\n(20,000 rows)", "Deduplicated\n(4,304 rows)", "10:1 Balanced\n(484 rows)"]
    benign_stages = [19956, unique_benign_count, n_target_benign]
    susp_stages = [44, 44, 44]
    
    x = np.arange(len(stages))
    width = 0.35
    ax.bar(x - width/2, benign_stages, width, label="Benign (0)", color="#2ecc71", edgecolor="black")
    ax.bar(x + width/2, susp_stages, width, label="Suspicious/Alert (1)", color="#e74c3c", edgecolor="black")
    ax.set_yscale("log")
    ax.set_ylim(1, 40000)
    ax.set_xticks(x)
    ax.set_xticklabels(stages)
    ax.set_ylabel("Record Count (Log Scale)", fontsize=11)
    ax.set_title("Progression of Dataset Balance Across Pipeline Stages", fontweight="bold", fontsize=12)
    ax.legend(loc="upper right")
    for i in range(len(stages)):
        ax.text(x[i] - width/2, benign_stages[i] * 1.3, f"{benign_stages[i]:,}", ha="center", fontsize=9, fontweight="bold")
        ax.text(x[i] + width/2, susp_stages[i] * 1.5, f"{susp_stages[i]}", ha="center", fontsize=9, fontweight="bold")
    fig.tight_layout()
    viz2 = os.path.join(VIZ_DIR, "phase7_before_after_balancing.png")
    fig.savefig(viz2, dpi=200)
    plt.close(fig)
    print(f"Saved: {viz2}")

    # 3. Balanced Dataset Event Type Distribution
    fig, ax = plt.subplots(figsize=(9, 5.5))
    et_counts = balanced_df["event_type"].value_counts().sort_values()
    colors = ["#e74c3c" if et == "auth_failure" else "#3498db" for et in et_counts.index]
    et_counts.plot(kind="barh", ax=ax, color=colors, edgecolor="black")
    ax.set_title("Event Type Distribution in Balanced Dataset (Red = Suspicious Class)", fontweight="bold", fontsize=12)
    ax.set_xlabel("Count", fontsize=11)
    for idx, (val, name) in enumerate(zip(et_counts.values, et_counts.index)):
        ax.text(val + 3, idx, f"{val}", va="center", fontsize=9, fontweight="bold")
    fig.tight_layout()
    viz3 = os.path.join(VIZ_DIR, "phase7_event_type_distribution.png")
    fig.savefig(viz3, dpi=200)
    plt.close(fig)
    print(f"Saved: {viz3}")

if __name__ == "__main__":
    execute_phase7()

