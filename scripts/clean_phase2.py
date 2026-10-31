"""
Phase 2: Individual Dataset Cleaning Script
SOC Dataset Preparation Pipeline for Qwen3-4B Fine-Tuning
"""

import os
import json
import ipaddress
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Ensure matplotlib works cleanly in sandbox
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"
os.makedirs("/tmp/matplotlib", exist_ok=True)
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams.update({"font.size": 11, "figure.autolayout": True})

SOURCE_PARQUET = "/tmp/soc_merged_sample.parquet"
OUTPUT_DIR = "outputs"
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
VIZ_DIR = os.path.join(OUTPUT_DIR, "visualizations")

NULL_STRINGS = {"", "nan", "none", "null", "nil", "-", "n/a", "na", "<na>", "undefined"}

IANA_PROTOCOLS = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPV6",
    "88": "KERBEROS",
    "89": "OSPF",
    "112": "VRRP",
    "115": "L2TP",
    "132": "SCTP",
}

def clean_null_string(val):
    if pd.isna(val) or val is None:
        return None
    s = str(val).strip()
    if s.lower() in NULL_STRINGS or s in ["N/A", "nan", "<NA>"]:
        return None
    return s

def validate_ip(ip_val):
    if pd.isna(ip_val) or ip_val is None:
        return None, True
    s = str(ip_val).strip()
    if s.lower() in NULL_STRINGS or s in ["N/A", "nan", "<NA>"]:
        return None, True
    try:
        ipaddress.ip_address(s)
        return s, True
    except ValueError:
        return None, False

def validate_port(port_val):
    if pd.isna(port_val) or port_val is None:
        return None, True
    try:
        p = int(port_val)
        if 0 <= p <= 65535:
            return p, True
        return None, False
    except (ValueError, TypeError):
        return None, False

def clean_dataset1(raw_df):
    """Clean Dataset 1: Advanced SIEM (synthetic_siem)."""
    df = raw_df.reset_index(drop=True)
    initial_count = len(df)
    
    # 1. Duplicates audit
    exact_dupes = int(df.duplicated().sum())
    id_dupes = int(df["event_id"].duplicated().sum())
    
    # Clean string nulls
    for col in ["source_ip", "dest_ip", "protocol", "user", "severity", "event_type", "source", "raw_log"]:
        if col in df.columns:
            df[col] = df[col].apply(clean_null_string)
            
    # Standardize IPs & check validity
    invalid_ips = 0
    clean_src_ips = []
    for ip in df["source_ip"]:
        clean_ip, is_valid = validate_ip(ip)
        clean_src_ips.append(clean_ip)
        if not is_valid:
            invalid_ips += 1
    df["source_ip"] = pd.Series(clean_src_ips, index=df.index, dtype="string")

    clean_dst_ips = []
    for ip in df["dest_ip"]:
        clean_ip, is_valid = validate_ip(ip)
        clean_dst_ips.append(clean_ip)
        if not is_valid:
            invalid_ips += 1
    df["dest_ip"] = pd.Series(clean_dst_ips, index=df.index, dtype="string")

    # Standardize Ports
    invalid_ports = 0
    clean_src_ports = []
    for p in df["source_port"]:
        cp, is_valid = validate_port(p)
        clean_src_ports.append(cp)
        if not is_valid:
            invalid_ports += 1
    df["source_port"] = pd.Series(clean_src_ports, index=df.index, dtype="Int64")

    clean_dst_ports = []
    for p in df["dest_port"]:
        cp, is_valid = validate_port(p)
        clean_dst_ports.append(cp)
        if not is_valid:
            invalid_ports += 1
    df["dest_port"] = pd.Series(clean_dst_ports, index=df.index, dtype="Int64")

    # Standardize Timestamps
    df["timestamp_raw"] = df["timestamp"].astype(str)
    ts_parsed = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    invalid_ts = int(ts_parsed.isna().sum())
    df["timestamp"] = ts_parsed.dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Standardize Protocol
    df["protocol"] = df["protocol"].str.upper()

    # Standardize Severity and Event Type
    df["severity"] = df["severity"].str.lower()
    df["event_type"] = df["event_type"].str.lower()

    # Preserve strictly unlabelled labels as per Instruction 4
    df["label"] = pd.Series([pd.NA] * len(df), index=df.index, dtype="Int64")
    df["label_text"] = "unlabeled"
    df["label_source"] = "unlabeled_pending_review"
    df["data_origin"] = "synthetic_siem"

    # Select standard columns
    cols_order = [
        "event_id", "timestamp", "timestamp_raw", "event_type", "source", "severity",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol", "user",
        "raw_log", "label", "label_text", "label_source", "data_origin"
    ]
    df_clean = df[cols_order].copy()
    
    # Missing value audit post-cleaning
    missing_audit = {}
    for col in df_clean.columns:
        null_cnt = int(df_clean[col].isna().sum())
        missing_audit[col] = {
            "missing_count": null_cnt,
            "missing_percentage": round((null_cnt / len(df_clean)) * 100, 2)
        }

    report = {
        "dataset_name": "Dataset 1 (Advanced SIEM / synthetic_siem)",
        "initial_record_count": initial_count,
        "cleaned_record_count": len(df_clean),
        "exact_duplicates_removed": exact_dupes,
        "duplicate_event_ids": id_dupes,
        "invalid_ips_found": invalid_ips,
        "invalid_ports_found": invalid_ports,
        "invalid_timestamps_found": invalid_ts,
        "missing_values_post_cleaning": missing_audit,
        "label_distribution": {
            "unlabeled": len(df_clean),
            "benign": 0,
            "suspicious": 0,
            "malicious": 0
        },
        "event_type_distribution": df_clean["event_type"].value_counts(dropna=False).to_dict(),
        "severity_distribution": df_clean["severity"].value_counts(dropna=False).to_dict(),
        "source_distribution_top10": df_clean["source"].value_counts(dropna=False).head(10).to_dict()
    }
    
    return df_clean, report

def clean_dataset2(raw_df):
    """Clean Dataset 2: WitFoo Precinct6 Signals (production_soc_sanitized)."""
    df = raw_df.reset_index(drop=True)
    initial_count = len(df)

    # 1. Duplicates audit
    exact_dupes = int(df.duplicated().sum())
    id_dupes = int(df["event_id"].duplicated().sum())

    # Clean string nulls (empty strings -> None)
    for col in ["source_ip", "dest_ip", "protocol", "user", "severity", "event_type", "source", "raw_log", "label_text"]:
        if col in df.columns:
            df[col] = df[col].apply(clean_null_string)

    # Standardize IPs & check validity
    invalid_ips = 0
    clean_src_ips = []
    for ip in df["source_ip"]:
        clean_ip, is_valid = validate_ip(ip)
        clean_src_ips.append(clean_ip)
        if not is_valid:
            invalid_ips += 1
    df["source_ip"] = pd.Series(clean_src_ips, index=df.index, dtype="string")

    clean_dst_ips = []
    for ip in df["dest_ip"]:
        clean_ip, is_valid = validate_ip(ip)
        clean_dst_ips.append(clean_ip)
        if not is_valid:
            invalid_ips += 1
    df["dest_ip"] = pd.Series(clean_dst_ips, index=df.index, dtype="string")

    # Standardize Ports
    invalid_ports = 0
    clean_src_ports = []
    for p in df["source_port"]:
        cp, is_valid = validate_port(p)
        clean_src_ports.append(cp)
        if not is_valid:
            invalid_ports += 1
    df["source_port"] = pd.Series(clean_src_ports, index=df.index, dtype="Int64")

    clean_dst_ports = []
    for p in df["dest_port"]:
        cp, is_valid = validate_port(p)
        clean_dst_ports.append(cp)
        if not is_valid:
            invalid_ports += 1
    df["dest_port"] = pd.Series(clean_dst_ports, index=df.index, dtype="Int64")

    # Standardize Timestamps from Unix epoch floats
    df["timestamp_raw"] = df["timestamp"].astype(str)
    ts_numeric = pd.to_numeric(df["timestamp"], errors="coerce")
    ts_parsed = pd.to_datetime(ts_numeric, unit="s", utc=True)
    invalid_ts = int(ts_parsed.isna().sum())
    df["timestamp"] = ts_parsed.dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Standardize Protocol: map IANA IDs to standard protocol names
    df["protocol_raw"] = df["protocol"].copy()
    df["protocol"] = df["protocol_raw"].map(
        lambda x: IANA_PROTOCOLS.get(str(x).strip(), str(x).strip().upper())
        if pd.notna(x) and x is not None and str(x).strip() != ""
        else None
    )

    # Standardize Severity and Event Type
    df["severity"] = df["severity"].str.lower()
    df["event_type"] = df["event_type"].str.lower()

    # Standardize and verify label_binary
    # Instruction 5: benign = 0, suspicious = 1, malicious = 2 (if present)
    df["label_raw"] = df["label_text"].astype(str).str.lower()
    label_map = {"benign": 0, "suspicious": 1, "malicious": 2}
    df["label"] = df["label_raw"].map(label_map).astype("Int64")
    df["label_text"] = df["label_raw"]
    df["label_source"] = "witfoo_label_binary"
    df["data_origin"] = "production_soc_sanitized"

    # Select standard columns
    cols_order = [
        "event_id", "timestamp", "timestamp_raw", "event_type", "source", "severity",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol", "protocol_raw",
        "user", "raw_log", "label", "label_text", "label_raw", "label_source", "data_origin"
    ]
    df_clean = df[cols_order].copy()

    # Missing value audit post-cleaning
    missing_audit = {}
    for col in df_clean.columns:
        null_cnt = int(df_clean[col].isna().sum())
        missing_audit[col] = {
            "missing_count": null_cnt,
            "missing_percentage": round((null_cnt / len(df_clean)) * 100, 2)
        }

    report = {
        "dataset_name": "Dataset 2 (WitFoo Precinct6 Signals / production_soc_sanitized)",
        "initial_record_count": initial_count,
        "cleaned_record_count": len(df_clean),
        "exact_duplicates_removed": exact_dupes,
        "duplicate_event_ids": id_dupes,
        "invalid_ips_found": invalid_ips,
        "invalid_ports_found": invalid_ports,
        "invalid_timestamps_found": invalid_ts,
        "missing_values_post_cleaning": missing_audit,
        "label_distribution": {
            "benign (0)": int((df_clean["label"] == 0).sum()),
            "suspicious (1)": int((df_clean["label"] == 1).sum()),
            "malicious (2)": int((df_clean["label"] == 2).sum()),
            "unlabeled": int(df_clean["label"].isna().sum())
        },
        "event_type_distribution": df_clean["event_type"].value_counts(dropna=False).to_dict(),
        "severity_distribution": df_clean["severity"].value_counts(dropna=False).to_dict(),
        "source_distribution_top10": df_clean["source"].value_counts(dropna=False).head(10).to_dict()
    }

    return df_clean, report

def generate_visualizations(ds1_clean, ds2_clean):
    """Generate professional diagnostic charts for label distributions and event types."""
    os.makedirs(VIZ_DIR, exist_ok=True)

    # 1. Dataset 1 Label Distribution
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(["Unlabeled\n(Pending Review)"], [len(ds1_clean)], color="#3498db", width=0.4, edgecolor="black")
    ax.set_title("Dataset 1 (Advanced SIEM) — Label Distribution", fontsize=13, fontweight="bold")
    ax.set_ylabel("Record Count", fontsize=11)
    ax.set_ylim(0, 115000)
    ax.text(0, len(ds1_clean) + 2000, f"{len(ds1_clean):,} (100%)", ha="center", fontweight="bold", fontsize=11)
    fig.tight_layout()
    fig.savefig(os.path.join(VIZ_DIR, "dataset1_label_distribution.png"), dpi=200)
    plt.close(fig)

    # 2. Dataset 2 Label Distribution
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    counts = [int((ds2_clean["label"] == 0).sum()), int((ds2_clean["label"] == 1).sum()), int((ds2_clean["label"] == 2).sum())]
    labels = ["Benign (0)", "Suspicious (1)", "Malicious (2)"]
    colors = ["#2ecc71", "#f39c12", "#e74c3c"]
    bars = ax.bar(labels, counts, color=colors, width=0.5, edgecolor="black")
    ax.set_title("Dataset 2 (WitFoo Signals) — Class Distribution & Severe Imbalance", fontsize=12, fontweight="bold")
    ax.set_ylabel("Record Count (Log Scale)", fontsize=11)
    ax.set_yscale("log")
    ax.set_ylim(0.5, 50000)
    for bar, count in zip(bars, counts):
        y_val = max(bar.get_height(), 1)
        ax.text(bar.get_x() + bar.get_width() / 2, y_val * 1.3, f"{count:,}", ha="center", fontweight="bold", fontsize=10)
    fig.tight_layout()
    fig.savefig(os.path.join(VIZ_DIR, "dataset2_label_distribution.png"), dpi=200)
    plt.close(fig)

    # 3. Dataset 1 Event Types
    fig, ax = plt.subplots(figsize=(9, 5))
    et1 = ds1_clean["event_type"].value_counts().sort_values()
    et1.plot(kind="barh", ax=ax, color="#1abc9c", edgecolor="black")
    ax.set_title("Dataset 1 (Advanced SIEM) — Event Type Distribution", fontsize=13, fontweight="bold")
    ax.set_xlabel("Count", fontsize=11)
    for idx, (val, name) in enumerate(zip(et1.values, et1.index)):
        ax.text(val + 100, idx, f"{val:,}", va="center", fontsize=9, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(VIZ_DIR, "dataset1_event_types.png"), dpi=200)
    plt.close(fig)

    # 4. Dataset 2 Event Types
    fig, ax = plt.subplots(figsize=(9, 5.5))
    et2 = ds2_clean["event_type"].value_counts().head(10).sort_values()
    et2.plot(kind="barh", ax=ax, color="#9b59b6", edgecolor="black")
    ax.set_title("Dataset 2 (WitFoo Signals) — Top 10 Event Types", fontsize=13, fontweight="bold")
    ax.set_xlabel("Count", fontsize=11)
    for idx, (val, name) in enumerate(zip(et2.values, et2.index)):
        ax.text(val + 50, idx, f"{val:,}", va="center", fontsize=9, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(VIZ_DIR, "dataset2_event_types.png"), dpi=200)
    plt.close(fig)

def main():
    print("Loading raw verified source archive...")
    raw_df = pd.read_parquet(SOURCE_PARQUET)
    
    ds1_raw = raw_df[raw_df["data_origin"] == "synthetic_siem"].copy()
    ds2_raw = raw_df[raw_df["data_origin"] == "production_soc_sanitized"].copy()
    
    print(f"Raw records -> Dataset 1: {len(ds1_raw)}, Dataset 2: {len(ds2_raw)}")
    
    # Clean Dataset 1
    print("\nCleaning Dataset 1...")
    ds1_clean, report1 = clean_dataset1(ds1_raw)
    out_ds1_path = os.path.join(OUTPUT_DIR, "dataset1_cleaned.csv")
    ds1_clean.to_csv(out_ds1_path, index=False)
    print(f"Saved: {out_ds1_path} ({len(ds1_clean)} records)")
    
    with open(os.path.join(REPORTS_DIR, "dataset1_analysis.json"), "w") as f:
        json.dump(report1, f, indent=2)
        
    # Clean Dataset 2
    print("\nCleaning Dataset 2...")
    ds2_clean, report2 = clean_dataset2(ds2_raw)
    out_ds2_path = os.path.join(OUTPUT_DIR, "dataset2_cleaned.csv")
    ds2_clean.to_csv(out_ds2_path, index=False)
    print(f"Saved: {out_ds2_path} ({len(ds2_clean)} records)")
    
    with open(os.path.join(REPORTS_DIR, "dataset2_analysis.json"), "w") as f:
        json.dump(report2, f, indent=2)
        
    # Visualizations
    print("\nGenerating Phase 2 visualizations...")
    generate_visualizations(ds1_clean, ds2_clean)
    print("Visualizations generated successfully.")

    # Copy script to outputs/scripts/dataset_preprocessing.py as requested
    with open(__file__, "r") as src, open(os.path.join(OUTPUT_DIR, "scripts", "dataset_preprocessing.py"), "w") as dst:
        dst.write(src.read())

    print("\nPhase 2 processing complete!")

if __name__ == "__main__":
    main()
