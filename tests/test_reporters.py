import os
import json
import tempfile

from scanner.findings import ScanResult, Severity, Finding
from scanner.reporters.json_reporter import JSONReporter
from scanner.reporters.html_reporter import HTMLReporter


def _make_result():
    result = ScanResult(project_id="test-project")
    result.add_finding(Finding(
        rule_id="GCP-FW-001",
        title="SSH open to world",
        description="Port 22 exposed to 0.0.0.0/0",
        severity=Severity.CRITICAL,
        resource_type="VPC Firewall Rule",
        resource_name="allow-ssh",
        project_id="test-project",
        remediation_steps="Delete the rule.",
        cis_benchmark="CIS GCP v2.0 - 3.6",
        terraform_fix='resource "google_compute_firewall" "fix" {}',
    ))
    result.add_finding(Finding(
        rule_id="GCP-LOG-001",
        title="Audit logs not enabled",
        description="DATA_READ missing",
        severity=Severity.HIGH,
        resource_type="Project Audit Config",
        resource_name="test-project",
        project_id="test-project",
        remediation_steps="Enable via gcloud.",
    ))
    result.finalize()
    return result


def test_json_reporter_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = JSONReporter(output_dir=tmpdir).write(_make_result(), filename="test.json")
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 1
        assert data["findings"][0]["rule_id"] == "GCP-FW-001"


def test_json_reporter_findings_sorted_by_severity():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = JSONReporter(output_dir=tmpdir).write(_make_result())
        with open(path) as f:
            data = json.load(f)
        severities = [f["severity"] for f in data["findings"]]
        assert severities[0] == "CRITICAL"
        assert severities[1] == "HIGH"


def test_html_reporter_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = HTMLReporter(output_dir=tmpdir).write(_make_result(), filename="test.html")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "SSH open to world" in content
        assert "GCP-FW-001" in content
        assert "CRITICAL" in content
        assert "google_compute_firewall" in content


def test_html_reporter_contains_cis_benchmark():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = HTMLReporter(output_dir=tmpdir).write(_make_result())
        with open(path) as f:
            content = f.read()
        assert "CIS GCP v2.0 - 3.6" in content


def test_html_reporter_empty_result():
    result = ScanResult(project_id="clean-project")
    result.finalize()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = HTMLReporter(output_dir=tmpdir).write(result)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "clean-project" in content


def test_html_reporter_includes_errors_section():
    result = ScanResult(project_id="test-project")
    result.add_error("Scanner 'sql' failed: 403 Forbidden")
    result.finalize()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = HTMLReporter(output_dir=tmpdir).write(result)
        with open(path) as f:
            content = f.read()
        assert "403 Forbidden" in content
