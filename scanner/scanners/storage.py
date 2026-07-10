import logging
from typing import List

from google.cloud import storage
from google.api_core.exceptions import Forbidden, NotFound

from scanner.base import BaseScanner
from scanner.findings import Finding, Severity
from scanner.remediation.terraform import get_terraform_fix


logger = logging.getLogger(__name__)

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class StorageScanner(BaseScanner):
    def __init__(self, project_id: str, credentials=None):
        super().__init__(project_id, credentials)
        self._gcs_client = storage.Client(project=project_id, credentials=credentials)

    def scan(self) -> List[Finding]:
        findings = []
        try:
            buckets = list(self._gcs_client.list_buckets())
        except Exception as exc:
            logger.warning("Could not list GCS buckets: %s", exc)
            return findings

        for bucket in buckets:
            try:
                bucket.reload()
                findings.extend(self._check_public_access(bucket))
                findings.extend(self._check_uniform_access(bucket))
                findings.extend(self._check_versioning(bucket))
                findings.extend(self._check_access_logging(bucket))
            except (Forbidden, NotFound) as exc:
                logger.warning("Could not inspect bucket %s: %s", bucket.name, exc)
            except Exception as exc:
                logger.warning("Error inspecting bucket %s: %s", bucket.name, exc)

        return findings

    def _check_public_access(self, bucket) -> List[Finding]:
        findings = []
        ctx = {"bucket_name": bucket.name, "project_id": self.project_id}
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
        except Exception:
            return findings

        for binding in policy.bindings:
            role = binding.get("role", "")
            members = binding.get("members", set())
            for member in members:
                if member not in PUBLIC_MEMBERS:
                    continue
                findings.append(Finding(
                    rule_id="GCP-GCS-001",
                    title=f"GCS bucket '{bucket.name}' is publicly accessible",
                    description=(
                        f"Bucket '{bucket.name}' grants '{role}' to '{member}'. "
                        f"{'allUsers means anyone without authentication can access this bucket.' if member == 'allUsers' else 'allAuthenticatedUsers means any Google account can access this bucket.'} "
                        "Any files present are fully exposed."
                    ),
                    severity=Severity.CRITICAL,
                    resource_type="Cloud Storage Bucket",
                    resource_name=bucket.name,
                    project_id=self.project_id,
                    remediation_steps=(
                        f"1. Remove public access:\n"
                        f"   gsutil iam ch -d {member}:{role.split('/')[-1]} gs://{bucket.name}\n"
                        "2. Enable uniform bucket-level access.\n"
                        "3. Use signed URLs for temporary external access."
                    ),
                    cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.1",
                    terraform_fix=get_terraform_fix("GCP-GCS-001", ctx),
                    evidence={"bucket": bucket.name, "role": role, "public_member": member},
                ))
        return findings

    def _check_uniform_access(self, bucket) -> List[Finding]:
        if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
            return [Finding(
                rule_id="GCP-GCS-002",
                title=f"Bucket '{bucket.name}' does not enforce uniform bucket-level access",
                description=(
                    f"Bucket '{bucket.name}' has uniform bucket-level access disabled. "
                    "Individual object ACLs can override bucket-level IAM policies, meaning a single "
                    "object could be publicly accessible even if the bucket IAM is restrictive."
                ),
                severity=Severity.MEDIUM,
                resource_type="Cloud Storage Bucket",
                resource_name=bucket.name,
                project_id=self.project_id,
                remediation_steps=(
                    f"gsutil uniformbucketlevelaccess set on gs://{bucket.name}\n"
                    "Note: once enabled, object-level ACLs are disabled. "
                    "Verify no services depend on them before enabling."
                ),
                cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.2",
                terraform_fix=get_terraform_fix("GCP-GCS-002", {"bucket_name": bucket.name}),
                evidence={"bucket": bucket.name},
            )]
        return []

    def _check_versioning(self, bucket) -> List[Finding]:
        if not bucket.versioning_enabled:
            return [Finding(
                rule_id="GCP-GCS-003",
                title=f"Versioning is disabled on bucket '{bucket.name}'",
                description=(
                    f"Bucket '{bucket.name}' does not have versioning enabled. Without versioning, "
                    "accidental deletion or overwrite of objects — by a bug, human error, or ransomware "
                    "— is unrecoverable."
                ),
                severity=Severity.LOW,
                resource_type="Cloud Storage Bucket",
                resource_name=bucket.name,
                project_id=self.project_id,
                remediation_steps=(
                    f"gsutil versioning set on gs://{bucket.name}\n"
                    "Consider adding a lifecycle rule to delete old versions after 30-90 days "
                    "to control storage costs."
                ),
                cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.3",
                terraform_fix=get_terraform_fix("GCP-GCS-003", {"bucket_name": bucket.name}),
                evidence={"bucket": bucket.name},
            )]
        return []

    def _check_access_logging(self, bucket) -> List[Finding]:
        logging_config = bucket.logging
        if not logging_config or not logging_config.get("logBucket"):
            return [Finding(
                rule_id="GCP-GCS-004",
                title=f"Access logging is disabled on bucket '{bucket.name}'",
                description=(
                    f"Bucket '{bucket.name}' does not have access logging enabled. Without access "
                    "logs, you cannot audit who accessed which objects or detect data exfiltration. "
                    "If a breach occurs, access logs are essential for forensics and timeline reconstruction."
                ),
                severity=Severity.LOW,
                resource_type="Cloud Storage Bucket",
                resource_name=bucket.name,
                project_id=self.project_id,
                remediation_steps=(
                    "1. Create a dedicated log bucket.\n"
                    f"2. Enable logging: gsutil logging set on -b gs://YOUR-LOG-BUCKET gs://{bucket.name}"
                ),
                cis_benchmark="CIS GCP Benchmark v2.0 - Control 5.4",
                terraform_fix=get_terraform_fix("GCP-GCS-004", {"bucket_name": bucket.name}),
                evidence={"bucket": bucket.name},
            )]
        return []
