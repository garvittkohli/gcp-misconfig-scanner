import logging
from typing import List

from googleapiclient import errors as google_errors

from scanner.base import BaseScanner
from scanner.findings import Finding, Severity
from scanner.remediation.terraform import get_terraform_fix


logger = logging.getLogger(__name__)


class LoggingScanner(BaseScanner):
    def scan(self) -> List[Finding]:
        findings = []
        try:
            findings.extend(self._check_audit_log_config())
        except Exception as exc:
            logger.warning("Audit log check failed: %s", exc)

        try:
            findings.extend(self._check_log_sinks())
        except Exception as exc:
            logger.warning("Log sink check failed: %s", exc)

        return findings

    def _check_audit_log_config(self) -> List[Finding]:
        try:
            policy = self.crm.projects().getIamPolicy(
                resource=self.project_id, body={}
            ).execute()
        except google_errors.HttpError as exc:
            logger.warning("Could not get IAM policy for audit log check: %s", exc)
            return []

        has_data_read = False
        has_data_write = False

        for config in policy.get("auditConfigs", []):
            if config.get("service") != "allServices":
                continue
            for log_config in config.get("auditLogConfigs", []):
                log_type = log_config.get("logType", "")
                if log_type == "DATA_READ":
                    has_data_read = True
                if log_type == "DATA_WRITE":
                    has_data_write = True

        missing = []
        if not has_data_read:
            missing.append("DATA_READ")
        if not has_data_write:
            missing.append("DATA_WRITE")

        if not missing:
            return []

        return [Finding(
            rule_id="GCP-LOG-001",
            title=f"Data Access audit logs ({', '.join(missing)}) not enabled for all services",
            description=(
                f"Cloud Audit Logs are not fully configured for project '{self.project_id}'. "
                f"Missing log types: {', '.join(missing)}. "
                "ADMIN_ACTIVITY is always on, but DATA_READ and DATA_WRITE are opt-in. "
                "Without DATA_READ logs, there is no record of who accessed sensitive data "
                "in Cloud Storage or Cloud SQL. Without DATA_WRITE, no record of what was modified."
            ),
            severity=Severity.HIGH,
            resource_type="Project Audit Config",
            resource_name=self.project_id,
            project_id=self.project_id,
            remediation_steps=(
                f"  gcloud projects get-iam-policy {self.project_id} > policy.yaml\n"
                "  # Add auditConfigs section with DATA_READ and DATA_WRITE for allServices\n"
                f"  gcloud projects set-iam-policy {self.project_id} policy.yaml"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 2.1",
            terraform_fix=get_terraform_fix("GCP-LOG-001", {"project_id": self.project_id}),
            evidence={"missing_log_types": missing},
        )]

    def _check_log_sinks(self) -> List[Finding]:
        try:
            response = self.logging_svc.projects().sinks().list(
                parent=f"projects/{self.project_id}"
            ).execute()
        except google_errors.HttpError as exc:
            logger.warning("Could not list log sinks: %s", exc)
            return []

        if response.get("sinks"):
            return []

        return [Finding(
            rule_id="GCP-LOG-002",
            title="No log sinks configured — audit logs are not being exported",
            description=(
                f"Project '{self.project_id}' has no logging sinks configured. "
                "Without a sink, logs are retained for only 30 days in Cloud Logging. "
                "An incident discovered after 31 days would have no forensic evidence. "
                "For ELK Stack integration, a Pub/Sub sink feeding into Logstash is the standard pattern."
            ),
            severity=Severity.MEDIUM,
            resource_type="Project Logging Config",
            resource_name=self.project_id,
            project_id=self.project_id,
            remediation_steps=(
                "Create a sink to export audit logs:\n"
                f"  gcloud logging sinks create audit-sink \\\n"
                f"    storage.googleapis.com/{self.project_id}-audit-logs \\\n"
                "    --log-filter='protoPayload.@type=type.googleapis.com/google.cloud.audit.AuditLog'"
            ),
            cis_benchmark="CIS GCP Benchmark v2.0 - Control 2.2",
            terraform_fix=get_terraform_fix("GCP-LOG-002", {"project_id": self.project_id}),
            evidence={"sink_count": 0},
        )]
