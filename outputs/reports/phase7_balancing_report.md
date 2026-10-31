# Phase 7: Class Balancing and Experimental Dataset Creation Report

## 1. Executive Summary

- **Deduplicated Dataset**: `4,304` records (`4,260` unique benign + `44` suspicious)
- **Balanced Experimental Dataset**: `484` records (`440` benign + `44` suspicious)
- **Balancing Ratio**: Exactly `10 : 1` (`90.91%` Benign : `9.09%` Suspicious/Alert)
- **Sampling Seed**: `42` (fully reproducible stratified proportional sample)

## 2. Deduplication Audit & Exclusions

Out of `19,956` raw benign records, `15,696` records (`78.65%`) were exact duplicates of recurring background daemon tasks.

| Excluded Event Type | Duplicate Rows Removed | Reason for Exclusion |
| :--- | :--- | :--- |
| `systemd_event` | 6,690 | Recurring background syslog/daemon telemetry with identical content |
| `diagnostic_event` | 3,033 | Recurring background syslog/daemon telemetry with identical content |
| `auth_event` | 1,855 | Recurring background syslog/daemon telemetry with identical content |
| `unknown` | 1,116 | Recurring background syslog/daemon telemetry with identical content |
| `communication` | 1,077 | Recurring background syslog/daemon telemetry with identical content |
| `auth_success` | 746 | Recurring background syslog/daemon telemetry with identical content |
| `access_log` | 746 | Recurring background syslog/daemon telemetry with identical content |
| `pam_event` | 372 | Recurring background syslog/daemon telemetry with identical content |
| `management_message` | 50 | Recurring background syslog/daemon telemetry with identical content |
| `integration_status` | 11 | Recurring background syslog/daemon telemetry with identical content |

## 3. Class Distribution: Before vs. After

| Stage | Total Records | Benign (0) | Suspicious (1) | Malicious (2) | Imbalance Ratio |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Raw Supervised | 20,000 | 19,956 (99.78%) | 44 (0.22%) | 0 (0.0%) | 453.54 : 1 |
| Deduplicated | 4,304 | 4,260 (98.98%) | 44 (1.02%) | 0 (0.0%) | 96.82 : 1 |
| **10:1 Balanced** | **484** | **440 (90.91%)** | **44 (9.09%)** | **0 (0.0%)** | **10.0 : 1** |

## 4. Final Assessment on Qwen3-4B Fine-Tuning Suitability

> [!WARNING]
> **Suitability Assessment**: This experimental dataset provides a clean proof-of-concept binary triage baseline, but **cannot support generalized production fine-tuning on its own**.
> 1. **Volume**: 484 records is minimal for adapting a 4-billion parameter LLM.
> 2. **Homogeneity**: The 44 suspicious records originate from only 2 hosts (`HOST-0002` and `HOST-0006`) with one single template (`Authentication failure`).
> 3. **Production Recommendation**: For final project deployment, retrieve confirmed incident IDs from the upstream 114M WitFoo dataset to introduce real multi-vector attacks.
