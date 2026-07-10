from scanner.remediation.terraform import get_terraform_fix


def test_ssh_fix_uses_iap_range():
    result = get_terraform_fix("GCP-FW-001", {
        "project_id": "my-project",
        "rule_name": "allow-ssh",
        "network": "default",
    })
    assert result is not None
    assert "google_compute_firewall" in result
    assert "35.235.240.0/20" in result


def test_rdp_fix_uses_iap_range():
    result = get_terraform_fix("GCP-FW-002", {
        "network": "default",
        "rule_name": "allow-rdp",
    })
    assert "35.235.240.0/20" in result
    assert "3389" in result


def test_public_bucket_fix():
    result = get_terraform_fix("GCP-GCS-001", {"bucket_name": "my-bucket"})
    assert "my-bucket" in result
    assert "google_storage_bucket" in result
    assert 'members = []' in result


def test_audit_logs_fix_includes_both_types():
    result = get_terraform_fix("GCP-LOG-001", {"project_id": "my-project"})
    assert "DATA_READ" in result
    assert "DATA_WRITE" in result
    assert "my-project" in result


def test_log_sink_fix_creates_bucket_and_sink():
    result = get_terraform_fix("GCP-LOG-002", {"project_id": "my-project"})
    assert "google_storage_bucket" in result
    assert "google_logging_project_sink" in result
    assert "my-project" in result


def test_sql_public_ip_fix_sets_ipv4_false():
    result = get_terraform_fix("GCP-SQL-001", {
        "instance_name": "my-db",
        "project_id": "my-project",
        "db_version": "POSTGRES_14",
    })
    assert "ipv4_enabled" in result
    assert "false" in result


def test_sql_open_network_fix():
    result = get_terraform_fix("GCP-SQL-003", {
        "instance_name": "my-db",
        "project_id": "my-project",
    })
    assert "authorized_networks" in result
    assert "cloud-sql-proxy" in result


def test_unknown_rule_returns_none():
    result = get_terraform_fix("GCP-UNKNOWN-999", {})
    assert result is None


def test_serial_port_fix():
    result = get_terraform_fix("GCP-COMP-003", {
        "instance_name": "my-vm",
        "zone": "us-central1-a",
    })
    assert "serial-port-enable" in result
    assert "false" in result


def test_fix_includes_resource_name_in_output():
    result = get_terraform_fix("GCP-GCS-002", {"bucket_name": "specific-bucket-name"})
    assert "specific-bucket-name" in result
