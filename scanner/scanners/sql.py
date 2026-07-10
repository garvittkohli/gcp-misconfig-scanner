import logging
from typing import List, Dict

from googleapiclient import errors as google_errors

from scanner.base import BaseScanner
from scanner.findings import Finding, Severity
from scanner.remediation.terraform import get_terraform_fix


logger = logging.getLogger(__name__)


class SQLScanner(BaseScanner):
    def scan(self) -> List[Finding]:
        findings = []
        try:
            instances = self._get_all_instances()
            for instance in instances:
                findings.extend(self._analyse_instance(instance))
        except Exception as exc:
            logger.warning("SQL scan failed: %s", exc)
        return findings

    def _get_all_instances(self) -> List[Dict]:
        try:
            response = self.sqladmin.instances().list(project=self.project_id).execute()
            return response.get("items", [])
        except google_errors.HttpError as exc:
            if exc.resp.status == 403:
                logger.warning("No permission to list Cloud SQL instances.")
            return []

    def _analyse_instance(self, instance: Dict) -> List[Finding]:
        findings = []
        name = instance.get("name", "unknown")
        db_version = instance.get("databaseVersion", "UNKNOWN")
        settings = instance.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        ctx = {"instance_name": name, "project_id": self.project_id, "db_version": db_version}

        findings.extend(self._check_public_ip(instance, name, ip_config, ctx))
        findings.extend(self._check_ssl_required(name, ip_config, ctx))
        findings.extend(self._check_authorized_networks(name, ip_config, ctx))
        findings.extend(self._check_backups(name, settings, ctx))

        return findings

    def _check_public_ip(self, instance, name, ip_config, ctx) -> List[Finding]:
        if not ip_config.get("ipv4Enabled", False):
            return []

        public_ips = [
            ip["ipAddress"] for ip in instance.get("ipAddresses", [])
            if ip.get("type") == "PRIMARY"
        ]
        ip_display = public_ips[0] if public_ips else "assigned"

        return [Finding(
            rule_id="GCP-SQL-001",
            title=f"Cloud SQL instance '{name}' has a public IP address",
            description=(
                f"Cloud SQL instance '{name}' ({ctx['db_version']}) has a public IP ({ip_display}). "
                "A database with a public IP can be reached directly from the internet. "
                "Use Private IP and Cloud SQL Auth Proxy for all connections."
            ),
            severity=Severity.HIGH,
            resource_type="Cloud SQL Instance",
            resource_name=name,
            project_id=self.project_id,
            remediation_steps=(
                "1. Enable Private IP and disable Public IP in Cloud SQL settings.\n"
                "2. Use Cloud SQL Auth Proxy for application connections:\n"
                f"   ./cloud-sql-proxy {self.project_id}:REGION:{name}\n"
                "3. Update application connection strings to use 127.0.0.1 via the proxy."
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.2",
            terraform_fix=get_terraform_fix("GCP-SQL-001", ctx),
            evidence={"public_ip": ip_display},
        )]

    def _check_ssl_required(self, name, ip_config, ctx) -> List[Finding]:
        if ip_config.get("requireSsl", False):
            return []
        return [Finding(
            rule_id="GCP-SQL-002",
            title=f"Cloud SQL instance '{name}' does not require SSL connections",
            description=(
                f"Cloud SQL instance '{name}' allows non-SSL connections. "
                "Without SSL, database credentials and query data travel as plaintext. "
                "On a shared network or any man-in-the-middle position, credentials can be intercepted."
            ),
            severity=Severity.MEDIUM,
            resource_type="Cloud SQL Instance",
            resource_name=name,
            project_id=self.project_id,
            remediation_steps=f"gcloud sql instances patch {name} --require-ssl",
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.4",
            terraform_fix=get_terraform_fix("GCP-SQL-002", ctx),
            evidence={"require_ssl": False},
        )]

    def _check_authorized_networks(self, name, ip_config, ctx) -> List[Finding]:
        findings = []
        for network in ip_config.get("authorizedNetworks", []):
            cidr = network.get("value", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                findings.append(Finding(
                    rule_id="GCP-SQL-003",
                    title=f"Cloud SQL instance '{name}' allows connections from 0.0.0.0/0",
                    description=(
                        f"Cloud SQL instance '{name}' has an authorized network of '{cidr}', "
                        "meaning any IP on the internet can attempt to connect. "
                        "Combined with a weak password or known authentication bypass, "
                        "this creates a directly exploitable database endpoint."
                    ),
                    severity=Severity.CRITICAL,
                    resource_type="Cloud SQL Instance",
                    resource_name=name,
                    project_id=self.project_id,
                    remediation_steps=(
                        f"1. Remove the 0.0.0.0/0 authorized network:\n"
                        f"   gcloud sql instances patch {name} --clear-authorized-networks\n"
                        "2. Use Cloud SQL Auth Proxy for application connections."
                    ),
                    cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.3",
                    terraform_fix=get_terraform_fix("GCP-SQL-003", ctx),
                    evidence={"authorized_network": cidr},
                ))
        return findings

    def _check_backups(self, name, settings, ctx) -> List[Finding]:
        if settings.get("backupConfiguration", {}).get("enabled", False):
            return []
        return [Finding(
            rule_id="GCP-SQL-004",
            title=f"Automated backups are disabled on Cloud SQL instance '{name}'",
            description=(
                f"Cloud SQL instance '{name}' has automated backups disabled. "
                "Data loss from accidental deletion, corruption, or ransomware "
                "would be permanent and unrecoverable."
            ),
            severity=Severity.MEDIUM,
            resource_type="Cloud SQL Instance",
            resource_name=name,
            project_id=self.project_id,
            remediation_steps=(
                f"gcloud sql instances patch {name} --backup-start-time=02:00"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 6.7",
            terraform_fix=get_terraform_fix("GCP-SQL-004", ctx),
            evidence={"backups_enabled": False},
        )]
