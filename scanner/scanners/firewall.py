import logging
from typing import List, Dict

from scanner.base import BaseScanner
from scanner.findings import Finding, Severity
from scanner.remediation.terraform import get_terraform_fix


logger = logging.getLogger(__name__)

CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    23: "Telnet",
}

DB_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1521: "Oracle DB",
    6379: "Redis",
    27017: "MongoDB",
    1433: "MSSQL",
}

OPEN_RANGES = {"0.0.0.0/0", "::/0"}


class FirewallScanner(BaseScanner):
    def scan(self) -> List[Finding]:
        findings = []
        try:
            rules = self._get_all_firewall_rules()
            for rule in rules:
                findings.extend(self._analyse_rule(rule))
        except Exception as exc:
            logger.warning("Firewall scan failed: %s", exc)
        return findings

    def _get_all_firewall_rules(self) -> List[Dict]:
        rules = []
        request = self.compute.firewalls().list(project=self.project_id)
        while request is not None:
            response = request.execute()
            rules.extend(response.get("items", []))
            request = self.compute.firewalls().list_next(
                previous_request=request, previous_response=response
            )
        return rules

    def _analyse_rule(self, rule: Dict) -> List[Finding]:
        findings = []

        if rule.get("direction", "INGRESS") != "INGRESS":
            return findings
        if rule.get("disabled", False):
            return findings

        rule_name = rule.get("name", "unknown")
        network_url = rule.get("network", "")
        network = network_url.split("/")[-1] if "/" in network_url else network_url
        source_ranges = rule.get("sourceRanges", [])
        allowed = rule.get("allowed", [])

        if not any(r in OPEN_RANGES for r in source_ranges):
            return findings

        ctx_base = {
            "project_id": self.project_id,
            "rule_name": rule_name,
            "network": network,
        }

        for allow_entry in allowed:
            protocol = allow_entry.get("IPProtocol", "")
            ports = allow_entry.get("ports", [])

            if protocol == "all" and not ports:
                findings.append(Finding(
                    rule_id="GCP-FW-003",
                    title=f"Firewall rule '{rule_name}' allows ALL traffic from the internet",
                    description=(
                        f"Rule '{rule_name}' on network '{network}' permits all protocols and all "
                        "ports from 0.0.0.0/0. This is equivalent to no firewall at all. Any instance "
                        "matching this rule's targets is fully exposed to the internet."
                    ),
                    severity=Severity.CRITICAL,
                    resource_type="VPC Firewall Rule",
                    resource_name=rule_name,
                    project_id=self.project_id,
                    remediation_steps=(
                        f"1. Immediately delete or disable rule '{rule_name}'.\n"
                        "2. Identify which instances were affected via target tags or targetServiceAccounts.\n"
                        "3. Replace with specific rules allowing only required ports from specific ranges."
                    ),
                    cis_benchmark="CIS GCP Benchmark v2.0 - Control 3.6",
                    terraform_fix=get_terraform_fix("GCP-FW-003", ctx_base),
                    evidence={"rule_name": rule_name, "network": network, "source_ranges": source_ranges},
                ))
                return findings

            for port_num in self._expand_ports(ports):
                if port_num in CRITICAL_PORTS:
                    label = CRITICAL_PORTS[port_num]
                    rule_id = "GCP-FW-001" if port_num == 22 else "GCP-FW-002"
                    ctx = {**ctx_base, "port": str(port_num), "label": label}

                    findings.append(Finding(
                        rule_id=rule_id,
                        title=f"{label} port {port_num} open to the entire internet via rule '{rule_name}'",
                        description=(
                            f"Firewall rule '{rule_name}' on network '{network}' allows {label} "
                            f"(port {port_num}/tcp) from 0.0.0.0/0. "
                            f"{'SSH exposure is how many crypto mining attacks begin — an attacker scans for open port 22 and attempts credential stuffing.' if port_num == 22 else 'RDP is the primary attack vector for ransomware deployments.'}"
                        ),
                        severity=Severity.CRITICAL,
                        resource_type="VPC Firewall Rule",
                        resource_name=rule_name,
                        project_id=self.project_id,
                        remediation_steps=(
                            f"1. Delete or disable rule '{rule_name}'.\n"
                            "2. Enable Identity-Aware Proxy (IAP) for tunneled access.\n"
                            "3. Allow only 35.235.240.0/20 (Google IAP range)."
                        ),
                        cis_benchmark="CIS GCP Benchmark v2.0 - Control 3.6",
                        terraform_fix=get_terraform_fix(rule_id, ctx),
                        evidence={
                            "rule_name": rule_name,
                            "port": port_num,
                            "protocol": protocol,
                            "source_ranges": source_ranges,
                        },
                    ))

                elif port_num in DB_PORTS:
                    label = DB_PORTS[port_num]
                    ctx = {**ctx_base, "port": str(port_num), "label": label}
                    findings.append(Finding(
                        rule_id="GCP-FW-004",
                        title=f"{label} port {port_num} exposed to 0.0.0.0/0 via rule '{rule_name}'",
                        description=(
                            f"Firewall rule '{rule_name}' exposes {label} port {port_num} to the "
                            "entire internet. Databases should never be directly reachable from the "
                            "public internet. This allows direct brute-force attacks and data exfiltration "
                            "if credentials are weak."
                        ),
                        severity=Severity.CRITICAL,
                        resource_type="VPC Firewall Rule",
                        resource_name=rule_name,
                        project_id=self.project_id,
                        remediation_steps=(
                            f"1. Delete rule '{rule_name}'.\n"
                            f"2. Restrict {label} to internal IP ranges only (10.x.x.x).\n"
                            "3. For Cloud SQL, use Cloud SQL Auth Proxy instead of direct port access."
                        ),
                        cis_benchmark="CIS GCP Benchmark v2.0 - Control 3.6",
                        terraform_fix=get_terraform_fix("GCP-FW-004", ctx),
                        evidence={"rule_name": rule_name, "port": port_num, "db_type": label},
                    ))

        return findings

    def _expand_ports(self, ports: List[str]) -> List[int]:
        """
        Expand port strings into integers.
        Uses range membership check for ranges to avoid materialising huge lists.
        """
        dangerous = set(CRITICAL_PORTS.keys()) | set(DB_PORTS.keys())
        result = []
        for p in ports:
            p = str(p)
            if "-" in p:
                try:
                    start, end = p.split("-")
                    start, end = int(start), int(end)
                    # only yield ports we actually check — avoids 65k-item lists
                    result.extend(d for d in dangerous if start <= d <= end)
                except ValueError:
                    pass
            else:
                try:
                    result.append(int(p))
                except ValueError:
                    pass
        return result
