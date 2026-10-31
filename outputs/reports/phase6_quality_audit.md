# Phase 6: In-Depth Quality Audit Report

**Audit Scope**: Master Merged Dataset (`120,000` rows) & Supervised Dataset (`20,000` rows)

## 1. Executive Summary & Core Quality Metrics

- **Total Master Records**: `120,000` (100k unlabelled + 19,956 benign + 44 suspicious)
- **Total Supervised Records**: `20,000` (19,956 benign + 44 suspicious + 0 malicious)
- **Class Imbalance Ratio (Supervised)**: `453.54 : 1`
- **Supervised Log Redundancy**: Only `2,256` unique raw logs across `20,000` rows (`88.7%` repetition)

## 2. Suspicious Records Deep-Dive (44 records)

- **Semantic Template**: 100% identical syslog format: `<142>Jul 26 11:10:... local1: Host: HOST-000X Duration: ... Count: ...; INFORMATIONAL: Authentication failure.`
- **Host Breakdown**: `HOST-0002` (23 records) and `HOST-0006` (21 records)
- **Missing Metadata**: 100% missing usernames, IPs, ports, and protocols.
- **Assessment**: Insufficient on their own for fine-tuning Qwen3-4B; model risks memorizing host tokens rather than security concepts.

## 3. Data Leakage and Spurious Correlation Vectors

1. **Deterministic Feature Leak**: `event_type == 'auth_failure'` is 100% predictive of class 1. Must be used as a target output, not input feature.
2. **Host Token Spuriousness**: `HOST-0002`/`0006` predict suspicious; `HOST-0001` predicts benign.
3. **Severity Inversion**: 52 `critical` events are benign; all 44 `suspicious` events are `informational`.

## 4. Missing Values Overview

| Column | Master Missing % | Supervised Missing % |
| :--- | :--- | :--- |
| `event_id` | 0.0% | 0.0% |
| `timestamp` | 0.0% | 0.0% |
| `timestamp_raw` | 0.0% | 0.0% |
| `event_type` | 0.0% | 0.0% |
| `source` | 0.0% | 0.0% |
| `severity` | 2.97% | 17.83% |
| `source_ip` | 55.27% | 80.62% |
| `dest_ip` | 69.42% | 84.36% |
| `source_port` | 89.0% | 96.25% |
| `dest_port` | 87.02% | 84.36% |
| `protocol` | 76.74% | 84.36% |
| `protocol_raw` | 97.39% | 84.36% |
| `user` | 57.47% | 96.26% |
| `raw_log` | 2.6% | 15.63% |
| `label` | 83.33% | 0.0% |
| `label_text` | 0.0% | 0.0% |
| `label_raw` | 83.33% | 0.0% |
| `label_source` | 0.0% | 0.0% |
| `data_origin` | 0.0% | 0.0% |
