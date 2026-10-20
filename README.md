# GCP Misconfiguration Scanner

[![CI](https://github.com/garvittkohli/gcp-misconfig-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/garvittkohli/gcp-misconfig-scanner/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Background

I built this after helping respond to a crypto mining compromise on our GCP infrastructure. Post-incident, I had no systematic way to check whether our configuration had drifted from what we'd intended - whether someone had added a permissive firewall rule, left a bucket public, or forgotten to enable audit logging. Google's Security Command Center solves this but at a cost that doesn't fit every team. Prowler and ScoutSuite cover hundreds of checks across multiple clouds but produce no remediation code. I wanted something that fit our actual workflow: findings that generate Terraform blocks, feeding directly into the same PR review process we use for all infrastructure changes.

## What It Does

Scans a GCP project across six services — IAM, Compute Engine, VPC Firewall, Cloud Storage, Cloud SQL, and Cloud Logging — for 23 specific misconfigurations, each mapped to a CIS GCP Foundation Benchmark v2.0 control. Every finding includes the exact Terraform HCL to fix it. Results can be shipped to Elasticsearch in ECS format for SIEM integration.

The tool is read-only. It never writes to GCP.

## Architecture

```
cli.py
  └── ScanEngine
        ├── IAMScanner      → primitive roles, public members, SA key age
        ├── ComputeScanner  → public IPs, OS Login, serial port, default SA
        ├── FirewallScanner → open SSH/RDP/DB ports, allow-all rules
        ├── StorageScanner  → public buckets, uniform access, versioning, logging
        ├── SQLScanner      → public IP, SSL, authorized networks, backups
        └── LoggingScanner  → audit log config, log sink existence
              │
              ├── HTMLReporter   → output/report.html
              ├── JSONReporter   → output/findings.json
              └── ELKShipper     → POST to Elasticsearch (optional)
```

## Installation

```bash
git clone https://github.com/garvittkohli/gcp-misconfig-scanner
cd gcp-misconfig-scanner
pip install -r requirements.txt
pip install -e .
```

## Authentication

```bash
# Local development
gcloud auth application-default login

# CI/CD or production
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
# or pass directly:
gcp-scan scan --project my-project --sa-key /path/to/key.json
```

Minimum IAM roles for the scanning service account:

| Role | Purpose |
|------|---------|
| `roles/viewer` | List compute, SQL, and project resources |
| `roles/iam.securityReviewer` | Read IAM policies and SA key metadata |
| `roles/storage.objectViewer` | Read bucket IAM policies |
| `roles/cloudsql.viewer` | Read Cloud SQL instance configuration |
| `roles/logging.viewer` | List log sinks and audit config |

## Usage

```bash
# Full scan — HTML + JSON reports in ./output/
gcp-scan scan --project YOUR_PROJECT_ID

# Terminal output only, no files written
gcp-scan quick-check --project YOUR_PROJECT_ID

# Scan one service
gcp-scan quick-check --project YOUR_PROJECT_ID --scanner firewall

# Generate a sample report with no GCP credentials needed
gcp-scan demo

# Skip a scanner
gcp-scan scan --project YOUR_PROJECT_ID --skip sql

# Ship findings to Elasticsearch
gcp-scan scan --project YOUR_PROJECT_ID --ship-elk

# CI/CD build gate — exits 1 on any CRITICAL finding
gcp-scan scan --project YOUR_PROJECT_ID --fail-on-critical --no-html
```

## Checks

| Rule ID | Severity | Description | CIS Control |
|---------|----------|-------------|-------------|
| GCP-IAM-001 | HIGH | Primitive Owner/Editor role assigned to user | 1.4/1.5 |
| GCP-IAM-002 | HIGH | Service account has primitive role | 1.5 |
| GCP-IAM-003 | MEDIUM | Service account key older than 90 days | 1.7 |
| GCP-IAM-004 | CRITICAL | allUsers/allAuthenticatedUsers in project IAM | 1.6 |
| GCP-FW-001 | CRITICAL | SSH port 22 open to 0.0.0.0/0 | 3.6 |
| GCP-FW-002 | CRITICAL | RDP port 3389 open to 0.0.0.0/0 | 3.6 |
| GCP-FW-003 | CRITICAL | All traffic allowed from 0.0.0.0/0 | 3.6 |
| GCP-FW-004 | CRITICAL | Database ports exposed to internet | 3.6 |
| GCP-GCS-001 | CRITICAL | GCS bucket publicly accessible | 5.1 |
| GCP-GCS-002 | MEDIUM | Uniform bucket-level access not enforced | 5.2 |
| GCP-GCS-003 | LOW | Bucket versioning disabled | 5.3 |
| GCP-GCS-004 | LOW | Bucket access logging disabled | 5.4 |
| GCP-SQL-001 | HIGH | Cloud SQL instance has public IP | 6.2 |
| GCP-SQL-002 | MEDIUM | SSL connections not required | 6.4 |
| GCP-SQL-003 | CRITICAL | 0.0.0.0/0 in authorized networks | 6.3 |
| GCP-SQL-004 | MEDIUM | Automated backups disabled | 6.7 |
| GCP-COMP-001 | MEDIUM | Compute instance has public external IP | 4.9 |
| GCP-COMP-002 | MEDIUM | OS Login not enabled | 4.4 |
| GCP-COMP-003 | MEDIUM | Serial port access enabled | 4.5 |
| GCP-COMP-004 | HIGH | Default SA with full cloud-platform scope | 4.1 |
| GCP-COMP-005 | LOW | Project-wide SSH keys not blocked | 4.3 |
| GCP-LOG-001 | HIGH | DATA_READ/DATA_WRITE audit logs not enabled | 2.1 |
| GCP-LOG-002 | MEDIUM | No log sinks configured | 2.2 |

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=scanner
```

## CI/CD Integration

```yaml
- name: GCP Security Scan
  run: |
    pip install -r requirements.txt
    gcp-scan scan \
      --project ${{ secrets.GCP_PROJECT_ID }} \
      --sa-key /tmp/sa-key.json \
      --fail-on-critical \
      --no-html
```

## License

MIT
