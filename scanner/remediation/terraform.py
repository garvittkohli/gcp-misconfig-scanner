from typing import Dict, Optional


def get_terraform_fix(rule_id: str, context: Dict) -> Optional[str]:
    generators = {
        "GCP-IAM-001": _fix_primitive_role,
        "GCP-IAM-002": _fix_sa_primitive_role,
        "GCP-IAM-003": _fix_sa_key_rotation,
        "GCP-IAM-004": _fix_public_iam_member,
        "GCP-FW-001":  _fix_open_ssh,
        "GCP-FW-002":  _fix_open_rdp,
        "GCP-FW-003":  _fix_open_all_ports,
        "GCP-FW-004":  _fix_open_db_port,
        "GCP-GCS-001": _fix_public_bucket,
        "GCP-GCS-002": _fix_uniform_access,
        "GCP-GCS-003": _fix_bucket_versioning,
        "GCP-GCS-004": _fix_bucket_logging,
        "GCP-SQL-001": _fix_sql_public_ip,
        "GCP-SQL-002": _fix_sql_no_ssl,
        "GCP-SQL-003": _fix_sql_open_network,
        "GCP-SQL-004": _fix_sql_no_backup,
        "GCP-COMP-001": _fix_compute_public_ip,
        "GCP-COMP-003": _fix_serial_port,
        "GCP-LOG-001": _fix_audit_logs,
        "GCP-LOG-002": _fix_log_sink,
    }
    generator = generators.get(rule_id)
    return generator(context) if generator else None


def _fix_primitive_role(ctx: Dict) -> str:
    return f"""# Remediation for GCP-IAM-001
# Remove primitive {ctx.get('role', 'roles/editor')} from {ctx.get('member', 'user')}
# then grant a least-privilege predefined role.

resource "google_project_iam_member" "remove_{ctx.get('rule_suffix', 'primitive_role')}" {{
  project = "{ctx.get('project_id', 'YOUR_PROJECT_ID')}"
  role    = "{ctx.get('role', 'roles/editor')}"
  member  = "{ctx.get('member', 'user:example@domain.com')}"
  # terraform destroy -target=... to remove this binding
}}

# Grant a scoped role instead:
# resource "google_project_iam_member" "scoped_role" {{
#   project = "{ctx.get('project_id', 'YOUR_PROJECT_ID')}"
#   role    = "roles/compute.instanceAdmin.v1"
#   member  = "{ctx.get('member', 'user:example@domain.com')}"
# }}"""


def _fix_sa_primitive_role(ctx: Dict) -> str:
    return f"""# Remediation for GCP-IAM-002

resource "google_project_iam_member" "remove_sa_primitive" {{
  project = "{ctx.get('project_id', 'YOUR_PROJECT_ID')}"
  role    = "{ctx.get('role', 'roles/editor')}"
  member  = "serviceAccount:{ctx.get('sa_email', 'sa@project.iam.gserviceaccount.com')}"
  # Run terraform destroy on this resource to remove the overprivileged binding.
}}"""


def _fix_sa_key_rotation(ctx: Dict) -> str:
    return f"""# Remediation for GCP-IAM-003
# Delete the old key:
# gcloud iam service-accounts keys delete {ctx.get('key_id', 'KEY_ID')} \\
#   --iam-account={ctx.get('sa_email', 'sa@project.iam.gserviceaccount.com')}

# Best practice: use Workload Identity Federation instead of key files.
# See: https://cloud.google.com/iam/docs/workload-identity-federation

resource "google_service_account_key" "rotated_key" {{
  service_account_id = "{ctx.get('sa_email', 'sa@project.iam.gserviceaccount.com')}"
}}"""


def _fix_public_iam_member(ctx: Dict) -> str:
    return f"""# Remediation for GCP-IAM-004
# Remove allUsers/allAuthenticatedUsers from project IAM.

resource "google_project_iam_binding" "remove_public_access" {{
  project = "{ctx.get('project_id', 'YOUR_PROJECT_ID')}"
  role    = "{ctx.get('role', 'roles/viewer')}"
  members = []
}}"""


def _fix_open_ssh(ctx: Dict) -> str:
    network = ctx.get('network', 'default')
    rule_name = ctx.get('rule_name', 'allow-ssh')
    return f"""# Remediation for GCP-FW-001
# Delete the permissive rule, then allow SSH only via IAP.

resource "google_compute_firewall" "allow_ssh_iap" {{
  name    = "allow-ssh-iap"
  network = "{network}"

  allow {{
    protocol = "tcp"
    ports    = ["22"]
  }}

  # 35.235.240.0/20 is Google's IAP range — the only source needed for IAP tunnels
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["ssh-via-iap"]
}}"""


def _fix_open_rdp(ctx: Dict) -> str:
    network = ctx.get('network', 'default')
    return f"""# Remediation for GCP-FW-002

resource "google_compute_firewall" "allow_rdp_iap" {{
  name    = "allow-rdp-iap"
  network = "{network}"

  allow {{
    protocol = "tcp"
    ports    = ["3389"]
  }}

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["rdp-via-iap"]
}}"""


def _fix_open_all_ports(ctx: Dict) -> str:
    network = ctx.get('network', 'default')
    rule_name = ctx.get('rule_name', 'allow-all')
    return f"""# Remediation for GCP-FW-003
# Delete rule '{rule_name}' entirely and replace with specific allow rules.

resource "google_compute_firewall" "{rule_name.replace('-','_')}_restricted" {{
  name    = "{rule_name}-restricted"
  network = "{network}"

  allow {{
    protocol = "tcp"
    ports    = ["443", "80"]
  }}

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["web-server"]
}}"""


def _fix_open_db_port(ctx: Dict) -> str:
    network = ctx.get('network', 'default')
    port = ctx.get('port', '3306')
    label = ctx.get('label', 'DB')
    return f"""# Remediation for GCP-FW-004

resource "google_compute_firewall" "allow_{label.lower()}_internal" {{
  name    = "allow-{label.lower()}-internal"
  network = "{network}"

  allow {{
    protocol = "tcp"
    ports    = ["{port}"]
  }}

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["db-client"]
}}"""


def _fix_public_bucket(ctx: Dict) -> str:
    bucket = ctx.get('bucket_name', 'YOUR_BUCKET_NAME')
    return f"""# Remediation for GCP-GCS-001

resource "google_storage_bucket_iam_binding" "remove_public_access" {{
  bucket  = "{bucket}"
  role    = "roles/storage.objectViewer"
  members = []
}}

resource "google_storage_bucket" "{bucket.replace('-','_')}" {{
  name                        = "{bucket}"
  uniform_bucket_level_access = true
}}"""


def _fix_uniform_access(ctx: Dict) -> str:
    bucket = ctx.get('bucket_name', 'YOUR_BUCKET_NAME')
    return f"""# Remediation for GCP-GCS-002

resource "google_storage_bucket" "{bucket.replace('-','_')}" {{
  name                        = "{bucket}"
  uniform_bucket_level_access = true
}}"""


def _fix_bucket_versioning(ctx: Dict) -> str:
    bucket = ctx.get('bucket_name', 'YOUR_BUCKET_NAME')
    return f"""# Remediation for GCP-GCS-003

resource "google_storage_bucket" "{bucket.replace('-','_')}" {{
  name = "{bucket}"

  versioning {{
    enabled = true
  }}
}}"""


def _fix_bucket_logging(ctx: Dict) -> str:
    bucket = ctx.get('bucket_name', 'YOUR_BUCKET_NAME')
    return f"""# Remediation for GCP-GCS-004

resource "google_storage_bucket" "access_logs" {{
  name = "{bucket}-access-logs"
}}

resource "google_storage_bucket" "{bucket.replace('-','_')}" {{
  name = "{bucket}"

  logging {{
    log_bucket        = "{bucket}-access-logs"
    log_object_prefix = "access-log-"
  }}
}}"""


def _fix_sql_public_ip(ctx: Dict) -> str:
    instance = ctx.get('instance_name', 'YOUR_SQL_INSTANCE')
    project = ctx.get('project_id', 'YOUR_PROJECT_ID')
    return f"""# Remediation for GCP-SQL-001

resource "google_sql_database_instance" "{instance.replace('-','_')}" {{
  name             = "{instance}"
  database_version = "{ctx.get('db_version', 'POSTGRES_14')}"
  project          = "{project}"

  settings {{
    tier = "db-f1-micro"

    ip_configuration {{
      ipv4_enabled    = false
      private_network = "projects/{project}/global/networks/default"
      require_ssl     = true
    }}
  }}

  deletion_protection = true
}}"""


def _fix_sql_no_ssl(ctx: Dict) -> str:
    instance = ctx.get('instance_name', 'YOUR_SQL_INSTANCE')
    return f"""# Remediation for GCP-SQL-002

resource "google_sql_database_instance" "{instance.replace('-','_')}" {{
  name = "{instance}"

  settings {{
    ip_configuration {{
      require_ssl = true
    }}
  }}
}}"""


def _fix_sql_open_network(ctx: Dict) -> str:
    instance = ctx.get('instance_name', 'YOUR_SQL_INSTANCE')
    return f"""# Remediation for GCP-SQL-003
# Remove open authorized network and use Cloud SQL Auth Proxy instead.

resource "google_sql_database_instance" "{instance.replace('-','_')}" {{
  name = "{instance}"

  settings {{
    ip_configuration {{
      dynamic "authorized_networks" {{
        for_each = []
        content {{}}
      }}
    }}
  }}
}}
# Connect via: cloud-sql-proxy {ctx.get('project_id', 'PROJECT')}:REGION:{instance}"""


def _fix_sql_no_backup(ctx: Dict) -> str:
    instance = ctx.get('instance_name', 'YOUR_SQL_INSTANCE')
    return f"""# Remediation for GCP-SQL-004

resource "google_sql_database_instance" "{instance.replace('-','_')}" {{
  name = "{instance}"

  settings {{
    backup_configuration {{
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }}
  }}
}}"""


def _fix_compute_public_ip(ctx: Dict) -> str:
    instance = ctx.get('instance_name', 'YOUR_INSTANCE')
    zone = ctx.get('zone', 'us-central1-a')
    return f"""# Remediation for GCP-COMP-001
# Remove the access_config block to drop the external IP.

resource "google_compute_instance" "{instance.replace('-','_')}" {{
  name = "{instance}"
  zone = "{zone}"

  network_interface {{
    network = "default"
    # no access_config block = no external IP
  }}
}}"""


def _fix_serial_port(ctx: Dict) -> str:
    instance = ctx.get('instance_name', 'YOUR_INSTANCE')
    zone = ctx.get('zone', 'us-central1-a')
    return f"""# Remediation for GCP-COMP-003

resource "google_compute_instance" "{instance.replace('-','_')}" {{
  name = "{instance}"
  zone = "{zone}"

  metadata = {{
    serial-port-enable = "false"
  }}
}}"""


def _fix_audit_logs(ctx: Dict) -> str:
    project = ctx.get('project_id', 'YOUR_PROJECT_ID')
    return f"""# Remediation for GCP-LOG-001

resource "google_project_iam_audit_config" "all_services" {{
  project = "{project}"
  service = "allServices"

  audit_log_config {{ log_type = "ADMIN_READ" }}
  audit_log_config {{ log_type = "DATA_READ" }}
  audit_log_config {{ log_type = "DATA_WRITE" }}
}}"""


def _fix_log_sink(ctx: Dict) -> str:
    project = ctx.get('project_id', 'YOUR_PROJECT_ID')
    return f"""# Remediation for GCP-LOG-002

resource "google_storage_bucket" "audit_logs" {{
  name                        = "{project}-audit-logs"
  location                    = "US"
  uniform_bucket_level_access = true
}}

resource "google_logging_project_sink" "audit_sink" {{
  name        = "audit-sink"
  project     = "{project}"
  destination = "storage.googleapis.com/${{google_storage_bucket.audit_logs.name}}"

  filter = "protoPayload.@type=\\"type.googleapis.com/google.cloud.audit.AuditLog\\""

  unique_writer_identity = true
}}

resource "google_storage_bucket_iam_member" "sink_writer" {{
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_sink.writer_identity
}}"""
