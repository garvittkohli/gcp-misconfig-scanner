from scanner.findings import Finding, Severity, ScanResult


def make_finding(severity=Severity.HIGH, rule_id="GCP-TEST-001"):
    return Finding(
        rule_id=rule_id,
        title="Test Finding",
        description="A test description",
        severity=severity,
        resource_type="Test Resource",
        resource_name="test-resource",
        project_id="test-project",
        remediation_steps="Fix it.",
    )


def test_finding_to_dict():
    f = make_finding()
    d = f.to_dict()
    assert d["rule_id"] == "GCP-TEST-001"
    assert d["severity"] == "HIGH"
    assert d["project_id"] == "test-project"
    assert "timestamp" in d


def test_finding_to_dict_optional_fields_default():
    f = make_finding()
    d = f.to_dict()
    assert d["cis_benchmark"] is None
    assert d["terraform_fix"] is None
    assert d["evidence"] == {}


def test_scan_result_summary():
    result = ScanResult(project_id="test-project")
    result.add_finding(make_finding(Severity.CRITICAL))
    result.add_finding(make_finding(Severity.HIGH))
    result.add_finding(make_finding(Severity.MEDIUM))
    result.finalize()

    s = result.summary()
    assert s["total_findings"] == 3
    assert s["critical"] == 1
    assert s["high"] == 1
    assert s["medium"] == 1
    assert s["low"] == 0


def test_scan_result_sorted_by_severity():
    result = ScanResult(project_id="test-project")
    result.add_finding(make_finding(Severity.LOW))
    result.add_finding(make_finding(Severity.CRITICAL))
    result.add_finding(make_finding(Severity.MEDIUM))

    sorted_findings = result.sorted_findings()
    assert sorted_findings[0].severity == Severity.CRITICAL
    assert sorted_findings[-1].severity == Severity.LOW


def test_scan_result_by_severity():
    result = ScanResult(project_id="test-project")
    result.add_finding(make_finding(Severity.CRITICAL))
    result.add_finding(make_finding(Severity.CRITICAL))
    result.add_finding(make_finding(Severity.HIGH))

    assert len(result.by_severity(Severity.CRITICAL)) == 2
    assert len(result.by_severity(Severity.HIGH)) == 1
    assert len(result.by_severity(Severity.LOW)) == 0


def test_scan_result_errors():
    result = ScanResult(project_id="test-project")
    result.add_error("Scanner X failed: 403")
    assert len(result.errors) == 1
    assert "403" in result.errors[0]


def test_finalize_sets_scan_end():
    result = ScanResult(project_id="test-project")
    assert result.scan_end is None
    result.finalize()
    assert result.scan_end is not None
