from scanner.scanners.firewall import FirewallScanner
from scanner.findings import Severity


def _make_scanner():
    s = FirewallScanner.__new__(FirewallScanner)
    s.project_id = "test-project"
    s.credentials = None
    s._compute_client = None
    return s


def _rule(name, protocol, ports, source_ranges, disabled=False, direction="INGRESS"):
    return {
        "name": name,
        "direction": direction,
        "disabled": disabled,
        "network": "global/networks/default",
        "sourceRanges": source_ranges,
        "allowed": [{"IPProtocol": protocol, "ports": ports}],
    }


def test_ssh_open_to_world_is_critical():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-ssh", "tcp", ["22"], ["0.0.0.0/0"])
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "GCP-FW-001"
    assert findings[0].terraform_fix is not None
    assert "35.235.240.0/20" in findings[0].terraform_fix


def test_rdp_open_to_world_is_critical():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-rdp", "tcp", ["3389"], ["0.0.0.0/0"])
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-002"
    assert findings[0].severity == Severity.CRITICAL


def test_all_ports_open_is_critical():
    rule = {
        "name": "allow-all",
        "direction": "INGRESS",
        "disabled": False,
        "network": "global/networks/default",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "all"}],
    }
    findings = _make_scanner()._analyse_rule(rule)
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-003"


def test_disabled_rule_not_flagged():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-ssh-disabled", "tcp", ["22"], ["0.0.0.0/0"], disabled=True)
    )
    assert len(findings) == 0


def test_restricted_source_not_flagged():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-ssh-internal", "tcp", ["22"], ["10.0.0.0/8"])
    )
    assert len(findings) == 0


def test_egress_rule_not_flagged():
    rule = _rule("allow-egress", "tcp", ["22"], ["0.0.0.0/0"])
    rule["direction"] = "EGRESS"
    findings = _make_scanner()._analyse_rule(rule)
    assert len(findings) == 0


def test_mysql_exposed_is_critical():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-mysql", "tcp", ["3306"], ["0.0.0.0/0"])
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-004"


def test_redis_exposed_is_critical():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-redis", "tcp", ["6379"], ["0.0.0.0/0"])
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-004"


def test_port_range_containing_ssh():
    # Range 20-25 contains port 22
    findings = _make_scanner()._analyse_rule(
        _rule("allow-range", "tcp", ["20-25"], ["0.0.0.0/0"])
    )
    rule_ids = [f.rule_id for f in findings]
    assert "GCP-FW-001" in rule_ids


def test_benign_https_not_flagged():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-https", "tcp", ["443"], ["0.0.0.0/0"])
    )
    assert len(findings) == 0


def test_ipv6_open_range_flagged():
    findings = _make_scanner()._analyse_rule(
        _rule("allow-ssh-ipv6", "tcp", ["22"], ["::/0"])
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "GCP-FW-001"
