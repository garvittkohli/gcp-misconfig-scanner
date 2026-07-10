import logging
from typing import List, Dict

from scanner.base import BaseScanner
from scanner.findings import Finding, Severity
from scanner.remediation.terraform import get_terraform_fix


logger = logging.getLogger(__name__)

DEFAULT_COMPUTE_SA_SUFFIX = "-compute@developer.gserviceaccount.com"


class ComputeScanner(BaseScanner):
    def scan(self) -> List[Finding]:
        findings = []
        try:
            instances = self._get_all_instances()
            for instance in instances:
                findings.extend(self._analyse_instance(instance))
        except Exception as exc:
            logger.warning("Compute scan failed: %s", exc)
        return findings

    def _get_all_instances(self) -> List[Dict]:
        instances = []
        request = self.compute.instances().aggregatedList(project=self.project_id)
        while request is not None:
            response = request.execute()
            for zone_data in response.get("items", {}).values():
                instances.extend(zone_data.get("instances", []))
            request = self.compute.instances().aggregatedList_next(
                previous_request=request, previous_response=response
            )
        return instances

    def _analyse_instance(self, instance: Dict) -> List[Finding]:
        findings = []
        name = instance.get("name", "unknown")
        zone_url = instance.get("zone", "")
        zone = zone_url.split("/")[-1] if "/" in zone_url else zone_url
        metadata_items = {
            item["key"]: item.get("value", "")
            for item in instance.get("metadata", {}).get("items", [])
        }
        ctx = {"instance_name": name, "zone": zone, "project_id": self.project_id}

        findings.extend(self._check_public_ip(instance, name, zone, ctx))
        findings.extend(self._check_os_login(name, zone, metadata_items))
        findings.extend(self._check_serial_port(name, zone, metadata_items, ctx))
        findings.extend(self._check_default_service_account(instance, name, zone))
        findings.extend(self._check_project_ssh_keys(name, zone, metadata_items))

        return findings

    def _check_public_ip(self, instance, name, zone, ctx) -> List[Finding]:
        findings = []
        for iface in instance.get("networkInterfaces", []):
            for ac in iface.get("accessConfigs", []):
                if ac.get("natIP"):
                    findings.append(Finding(
                        rule_id="GCP-COMP-001",
                        title=f"Instance '{name}' has a public external IP address",
                        description=(
                            f"Instance '{name}' in zone '{zone}' has external IP {ac['natIP']} assigned. "
                            "Public IPs expose the instance directly to the internet. "
                            "Use Cloud NAT for outbound internet access and IAP for admin access."
                        ),
                        severity=Severity.MEDIUM,
                        resource_type="Compute Instance",
                        resource_name=name,
                        project_id=self.project_id,
                        remediation_steps=(
                            "1. Remove the external IP: VM instance → Edit → Network interfaces → External IP → None.\n"
                            "2. Set up Cloud NAT for outbound internet access.\n"
                            "3. Use IAP for SSH/RDP access."
                        ),
                        cis_benchmark="CIS GCP Benchmark v2.0 - Control 4.9",
                        terraform_fix=get_terraform_fix("GCP-COMP-001", ctx),
                        evidence={"public_ip": ac["natIP"], "zone": zone},
                    ))
        return findings

    def _check_os_login(self, name, zone, metadata_items) -> List[Finding]:
        val = metadata_items.get("enable-oslogin", "").lower()
        if val in ("false", "0") or not val:
            return [Finding(
                rule_id="GCP-COMP-002",
                title=f"OS Login is not enabled on instance '{name}'",
                description=(
                    f"Instance '{name}' does not have OS Login enabled. Without OS Login, "
                    "SSH access is managed through SSH keys stored in metadata. "
                    "When you offboard a developer you must manually remove their key from every VM. "
                    "OS Login ties SSH access to IAM identities — revoking IAM access also revokes SSH."
                ),
                severity=Severity.MEDIUM,
                resource_type="Compute Instance",
                resource_name=name,
                project_id=self.project_id,
                remediation_steps=(
                    f"gcloud compute instances add-metadata {name} --zone={zone} "
                    "--metadata enable-oslogin=TRUE"
                ),
                cis_benchmark="CIS GCP Benchmark v2.0 - Control 4.4",
                terraform_fix=(
                    f'resource "google_compute_instance" "{name.replace("-","_")}" {{\n'
                    f'  name = "{name}"\n  zone = "{zone}"\n\n'
                    '  metadata = {\n    enable-oslogin = "TRUE"\n  }\n}}'
                ),
                evidence={"os_login_value": val or "not set"},
            )]
        return []

    def _check_serial_port(self, name, zone, metadata_items, ctx) -> List[Finding]:
        val = metadata_items.get("serial-port-enable", "0").lower()
        if val in ("true", "1", "yes"):
            return [Finding(
                rule_id="GCP-COMP-003",
                title=f"Serial port access is enabled on instance '{name}'",
                description=(
                    f"Instance '{name}' has interactive serial port access enabled. "
                    "Serial port access allows connecting to an instance through a console that "
                    "bypasses normal SSH access controls. An attacker with compromised GCP credentials "
                    "can use this even if all firewall rules are blocking network access."
                ),
                severity=Severity.MEDIUM,
                resource_type="Compute Instance",
                resource_name=name,
                project_id=self.project_id,
                remediation_steps=(
                    f"gcloud compute instances add-metadata {name} "
                    f"--zone={zone} --metadata serial-port-enable=false"
                ),
                cis_benchmark="CIS GCP Benchmark v2.0 - Control 4.5",
                terraform_fix=get_terraform_fix("GCP-COMP-003", ctx),
                evidence={"serial_port_enable": val},
            )]
        return []

    def _check_default_service_account(self, instance, name, zone) -> List[Finding]:
        findings = []
        for sa in instance.get("serviceAccounts", []):
            email = sa.get("email", "")
            scopes = sa.get("scopes", [])
            if email.endswith(DEFAULT_COMPUTE_SA_SUFFIX):
                if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                    findings.append(Finding(
                        rule_id="GCP-COMP-004",
                        title=f"Instance '{name}' uses default compute SA with full cloud-platform scope",
                        description=(
                            f"Instance '{name}' uses the default Compute Engine service account "
                            f"({email}) with the 'cloud-platform' scope. "
                            "The default service account has the Editor primitive role — code running "
                            "on this VM can read, modify, or delete any resource in the project. "
                            "If the VM is compromised via SSRF or RCE, the attacker inherits these permissions."
                        ),
                        severity=Severity.HIGH,
                        resource_type="Compute Instance",
                        resource_name=name,
                        project_id=self.project_id,
                        remediation_steps=(
                            "1. Create a dedicated service account with only the permissions this VM needs.\n"
                            "2. Assign it to the instance with specific OAuth scopes.\n"
                            f"   gcloud compute instances set-service-account {name} --zone={zone} "
                            "--service-account=DEDICATED_SA_EMAIL --scopes=SPECIFIC_SCOPES"
                        ),
                        cis_benchmark="CIS GCP Benchmark v2.0 - Control 4.1",
                        terraform_fix=None,
                        evidence={"sa_email": email, "scopes": scopes},
                    ))
        return findings

    def _check_project_ssh_keys(self, name, zone, metadata_items) -> List[Finding]:
        val = metadata_items.get("block-project-ssh-keys", "false").lower()
        if val not in ("true", "1", "yes"):
            return [Finding(
                rule_id="GCP-COMP-005",
                title=f"Instance '{name}' allows project-wide SSH keys",
                description=(
                    f"Instance '{name}' does not block project-level SSH keys. "
                    "Project-wide SSH keys give access to all instances in the project. "
                    "SSH access should be instance-specific or managed through OS Login."
                ),
                severity=Severity.LOW,
                resource_type="Compute Instance",
                resource_name=name,
                project_id=self.project_id,
                remediation_steps=(
                    f"gcloud compute instances add-metadata {name} --zone={zone} "
                    "--metadata block-project-ssh-keys=TRUE"
                ),
                cis_benchmark="CIS GCP Benchmark v2.0 - Control 4.3",
                terraform_fix=(
                    f'resource "google_compute_instance" "{name.replace("-","_")}" {{\n'
                    f'  name = "{name}"\n  zone = "{zone}"\n\n'
                    '  metadata = {\n    block-project-ssh-keys = "TRUE"\n  }\n}}'
                ),
                evidence={"block_project_ssh_keys": val},
            )]
        return []
