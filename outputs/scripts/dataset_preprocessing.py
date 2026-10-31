"""
End-to-End SOC Dataset Preprocessing Pipeline
Phases 2 - 7: Cleaning, Standardization, Merging, Deduplication, and 10:1 Balancing
For Future Qwen3-4B SOC Fine-Tuning
"""

import os
import json
import ipaddress
import pandas as pd
import numpy as np

OUTPUT_DIR = "outputs"
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
VIZ_DIR = os.path.join(OUTPUT_DIR, "visualizations")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(VIZ_DIR, exist_ok=True)

NULL_STRINGS = {"", "nan", "none", "null", "nil", "-", "n/a", "na", "<na>", "undefined"}

IANA_PROTOCOLS = {
    "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP",
    "51": "AH", "58": "ICMPV6", "88": "KERBEROS", "89": "OSPF",
    "112": "VRRP", "115": "L2TP", "132": "SCTP",
}

RANDOM_SEED = 42

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
    df = raw_df.reset_index(drop=True)
    for col in ["source_ip", "dest_ip", "protocol", "user", "severity", "event_type", "source", "raw_log"]:
        if col in df.columns:
            df[col] = df[col].apply(clean_null_string)

    df["source_ip"] = pd.Series([validate_ip(ip)[0] for ip in df["source_ip"]], index=df.index, dtype="string")
    df["dest_ip"] = pd.Series([validate_ip(ip)[0] for ip in df["dest_ip"]], index=df.index, dtype="string")
    df["source_port"] = pd.Series([validate_port(p)[0] for p in df["source_port"]], index=df.index, dtype="Int64")
    df["dest_port"] = pd.Series([validate_port(p)[0] for p in df["dest_port"]], index=df.index, dtype="Int64")

    df["timestamp_raw"] = df["timestamp"].astype(str)
    ts_parsed = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["timestamp"] = ts_parsed.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    df["protocol"] = df["protocol"].str.upper()
    df["severity"] = df["severity"].str.lower()
    df["event_type"] = df["event_type"].str.lower()

    df["label"] = pd.Series([pd.NA] * len(df), index=df.index, dtype="Int64")
    df["label_text"] = "unlabeled"
    df["label_source"] = "unlabeled_pending_review"
    df["data_origin"] = "synthetic_siem"

    cols = [
        "event_id", "timestamp", "timestamp_raw", "event_type", "source", "severity",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol", "user",
        "raw_log", "label", "label_text", "label_source", "data_origin"
    ]
    return df[cols].copy()

def clean_dataset2(raw_df):
    df = raw_df.reset_index(drop=True)
    for col in ["source_ip", "dest_ip", "protocol", "user", "severity", "event_type", "source", "raw_log", "label_text"]:
        if col in df.columns:
            df[col] = df[col].apply(clean_null_string)

    df["source_ip"] = pd.Series([validate_ip(ip)[0] for ip in df["source_ip"]], index=df.index, dtype="string")
    df["dest_ip"] = pd.Series([validate_ip(ip)[0] for ip in df["dest_ip"]], index=df.index, dtype="string")
    df["source_port"] = pd.Series([validate_port(p)[0] for p in df["source_port"]], index=df.index, dtype="Int64")
    df["dest_port"] = pd.Series([validate_port(p)[0] for p in df["dest_port"]], index=df.index, dtype="Int64")

    df["timestamp_raw"] = df["timestamp"].astype(str)
    ts_numeric = pd.to_numeric(df["timestamp"], errors="coerce")
    ts_parsed = pd.to_datetime(ts_numeric, unit="s", utc=True)
    df["timestamp"] = ts_parsed.dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    df["protocol_raw"] = df["protocol"].copy()
    df["protocol"] = df["protocol_raw"].map(
        lambda x: IANA_PROTOCOLS.get(str(x).strip(), str(x).strip().upper())
        if pd.notna(x) and x is not None and str(x).strip() != ""
        else None
    )

    df["severity"] = df["severity"].str.lower()
    df["event_type"] = df["event_type"].str.lower()

    df["label_raw"] = df["label_text"].astype(str).str.lower()
    label_map = {"benign": 0, "suspicious": 1, "malicious": 2}
    df["label"] = df["label_raw"].map(label_map).astype("Int64")
    df["label_text"] = df["label_raw"]
    df["label_source"] = "witfoo_label_binary"
    df["data_origin"] = "production_soc_sanitized"

    cols = [
        "event_id", "timestamp", "timestamp_raw", "event_type", "source", "severity",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol", "protocol_raw",
        "user", "raw_log", "label", "label_text", "label_raw", "label_source", "data_origin"
    ]
    return df[cols].copy()

def deduplicate_and_balance(supervised_df, seed=RANDOM_SEED, ratio=10):
    benign_raw = supervised_df[supervised_df["label"] == 0].copy().reset_index(drop=True)
    susp_raw = supervised_df[supervised_df["label"] == 1].copy().reset_index(drop=True)

    feat_cols = [
        "event_type", "source", "severity", "source_ip", "dest_ip",
        "source_port", "dest_port", "protocol", "user", "raw_log"
    ]

    is_benign_dup = benign_raw.duplicated(subset=feat_cols, keep="first")
    unique_benign = benign_raw[~is_benign_dup].copy().reset_index(drop=True)
    unique_susp = susp_raw.drop_duplicates(subset=feat_cols, keep="first").copy().reset_index(drop=True)

    dedup_df = pd.concat([unique_benign, unique_susp], ignore_index=True, sort=False)
    dedup_df["label_text"] = dedup_df["label"].map({0: "benign", 1: "suspicious/alert"})

    n_target_benign = min(len(unique_susp) * ratio, len(unique_benign))
    proportions = unique_benign["event_type"].value_counts(normalize=True)
    allocations = (proportions * (n_target_benign - len(proportions))).round().astype(int) + 1
    diff = n_target_benign - allocations.sum()
    allocations.iloc[0] += diff

    sampled_benign_parts = []
    for et, count in allocations.items():
        sub = unique_benign[unique_benign["event_type"] == et]
        sampled_benign_parts.append(sub.sample(n=min(count, len(sub)), random_state=seed))

    sampled_benign = pd.concat(sampled_benign_parts).reset_index(drop=True)
    sampled_benign["label_text"] = "benign"
    unique_susp_balanced = unique_susp.copy()
    unique_susp_balanced["label_text"] = "suspicious/alert"

    balanced_df = pd.concat([sampled_benign, unique_susp_balanced], ignore_index=True, sort=False)
    return dedup_df, balanced_df

def main():
    print("Running end-to-end dataset preprocessing pipeline...")
    df1 = pd.read_csv(os.path.join(OUTPUT_DIR, "dataset1_cleaned.csv"))
    df2 = pd.read_csv(os.path.join(OUTPUT_DIR, "dataset2_cleaned.csv"))

    if "protocol_raw" not in df1.columns:
        df1["protocol_raw"] = pd.Series([pd.NA] * len(df1), dtype="string")
    if "label_raw" not in df1.columns:
        df1["label_raw"] = pd.Series([pd.NA] * len(df1), dtype="string")

    unified_columns = [
        "event_id", "timestamp", "timestamp_raw", "event_type", "source", "severity",
        "source_ip", "dest_ip", "source_port", "dest_port", "protocol", "protocol_raw",
        "user", "raw_log", "label", "label_text", "label_raw", "label_source", "data_origin"
    ]

    master_df = pd.concat([df1[unified_columns], df2[unified_columns]], ignore_index=True, sort=False)
    supervised_df = master_df[master_df["label"].notna()].copy().reset_index(drop=True)

    dedup_df, balanced_df = deduplicate_and_balance(supervised_df)

    print(f"Master merged: {master_df.shape}")
    print(f"Supervised labelled: {supervised_df.shape}")
    print(f"Deduplicated labelled: {dedup_df.shape}")
    print(f"Balanced (10:1): {balanced_df.shape}")

if __name__ == "__main__":
    main()
