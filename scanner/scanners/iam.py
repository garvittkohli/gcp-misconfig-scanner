import logging
from typing import List
from datetime import datetime, timezone

from googleapiclient import errors as google_errors
from dateutil import parser as dateutil_parser

from scanner.base import BaseScanner
from scanner.findings import Finding, Severity
from scanner.remediation.terraform import get_terraform_fix


logger = logging.getLogger(__name__)

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class IAMScanner(BaseScanner):
    def scan(self) -> List[Finding]:
        findings = []
        try:
            findings.extend(self._check_primitive_roles())
        except Exception as exc:
            logger.warning("IAM primitive role check failed: %s", exc)

        try:
            findings.extend(self._check_public_iam_members())
        except Exception as exc:
            logger.warning("IAM public member check failed: %s", exc)

        try:
            findings.extend(self._check_service_account_keys())
        except Exception as exc:
            logger.warning("Service account key check failed: %s", exc)

        return findings

    def _get_project_iam_policy(self):
        return self.crm.projects().getIamPolicy(
            resource=self.project_id, body={}
        ).execute()

    def _check_primitive_roles(self) -> List[Finding]:
        findings = []
        policy = self._get_project_iam_policy()

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            if role not in PRIMITIVE_ROLES:
                continue

            for member in binding.get("members", []):
                if member in PUBLIC_MEMBERS:
                    continue

                member_type = member.split(":")[0] if ":" in member else member

                if member_type == "user":
                    rule_id = "GCP-IAM-001"
                    severity = Severity.HIGH
                    title = f"Primitive role {role} assigned to user account"
                    description = (
                        f"User '{member}' has the primitive role '{role}' on project "
                        f"'{self.project_id}'. Primitive roles grant broad permissions across all "
                        "GCP services and violate the principle of least privilege. An attacker who "
                        "compromises this account gains near-total control of the project."
                    )
                    cis = "1.4" if role == "roles/owner" else "1.5"
                elif member_type == "serviceAccount":
                    rule_id = "GCP-IAM-002"
                    severity = Severity.HIGH
                    title = f"Service account has primitive role {role}"
                    description = (
                        f"Service account '{member}' has primitive role '{role}'. "
                        "If this service account's key is leaked or the attached VM is compromised, "
                        "an attacker can perform any action on the project."
                    )
                    cis = "1.5"
                else:
                    continue

                suffix = member.replace(":", "_").replace("@", "_").replace(".", "_")[:30]
                ctx = {
                    "project_id": self.project_id,
                    "role": role,
                    "member": member,
                    "rule_suffix": suffix,
                    "sa_email": member.replace("serviceAccount:", ""),
                }

                findings.append(Finding(
                    rule_id=rule_id,
                    title=title,
                    description=description,
                    severity=severity,
                    resource_type="IAM Policy Binding",
                    resource_name=f"{self.project_id}/{role}/{member}",
                    project_id=self.project_id,
                    remediation_steps=(
                        f"1. Identify the minimum permissions the principal actually needs.\n"
                        f"2. Grant a specific predefined role (e.g., roles/compute.instanceAdmin.v1).\n"
                        f"3. Remove the {role} binding:\n"
                        f"   gcloud projects remove-iam-policy-binding {self.project_id} "
                        f"--member='{member}' --role='{role}'"
                    ),
                    cis_benchmark=f"CIS GCP Benchmark v2.0 - Control {cis}",
                    terraform_fix=get_terraform_fix(rule_id, ctx),
                    evidence={"role": role, "member": member},
                ))

        return findings

    def _check_public_iam_members(self) -> List[Finding]:
        findings = []
        policy = self._get_project_iam_policy()

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            for member in binding.get("members", []):
                if member not in PUBLIC_MEMBERS:
                    continue

                findings.append(Finding(
                    rule_id="GCP-IAM-004",
                    title=f"Public member '{member}' has role {role} on project",
                    description=(
                        f"The member '{member}' has role '{role}' on project '{self.project_id}'. "
                        "'allUsers' means anyone on the internet, authenticated or not. "
                        "This is a critical misconfiguration — project resources are publicly accessible."
                    ),
                    severity=Severity.CRITICAL,
                    resource_type="IAM Policy Binding",
                    resource_name=f"{self.project_id}/{role}/{member}",
                    project_id=self.project_id,
                    remediation_steps=(
                        f"Immediately remove the public IAM binding:\n"
                        f"   gcloud projects remove-iam-policy-binding {self.project_id} "
                        f"--member='{member}' --role='{role}'"
                    ),
                    cis_benchmark="CIS GCP Benchmark v2.0 - Control 1.6",
                    terraform_fix=get_terraform_fix("GCP-IAM-004", {
                        "project_id": self.project_id,
                        "role": role,
                    }),
                    evidence={"role": role, "member": member},
                ))

        return findings

    def _check_service_account_keys(self) -> List[Finding]:
        findings = []
        max_age_days = 90

        try:
            sa_list = self.iam.projects().serviceAccounts().list(
                name=f"projects/{self.project_id}"
            ).execute()
        except google_errors.HttpError as exc:
            logger.warning("Could not list service accounts: %s", exc)
            return findings

        for sa in sa_list.get("accounts", []):
            sa_email = sa.get("email", "")
            sa_name = sa.get("name", "")

            try:
                keys_response = self.iam.projects().serviceAccounts().keys().list(
                    name=sa_name,
                    keyTypes=["USER_MANAGED"]
                ).execute()
            except google_errors.HttpError:
                continue

            for key in keys_response.get("keys", []):
                created_str = key.get("validAfterTime", "")
                if not created_str:
                    continue

                try:
                    created_dt = dateutil_parser.isoparse(created_str)
                    age_days = (datetime.now(timezone.utc) - created_dt).days
                except Exception:
                    continue

                if age_days > max_age_days:
                    key_id = key.get("name", "").split("/")[-1]
                    findings.append(Finding(
                        rule_id="GCP-IAM-003",
                        title=f"Service account key is {age_days} days old (exceeds {max_age_days} days)",
                        description=(
                            f"Service account '{sa_email}' has a user-managed key (ID: {key_id}) "
                            f"created {age_days} days ago. Keys older than {max_age_days} days increase "
                            "the risk window if the key is ever compromised or leaked."
                        ),
                        severity=Severity.MEDIUM,
                        resource_type="Service Account Key",
                        resource_name=sa_email,
                        project_id=self.project_id,
                        remediation_steps=(
                            f"1. Delete old key: gcloud iam service-accounts keys delete {key_id} "
                            f"--iam-account={sa_email}\n"
                            "2. Create a replacement key if still needed.\n"
                            "3. Best practice: migrate to Workload Identity Federation to eliminate keys entirely."
                        ),
                        cis_benchmark="CIS GCP Benchmark v2.0 - Control 1.7",
                        terraform_fix=get_terraform_fix("GCP-IAM-003", {
                            "sa_email": sa_email,
                            "key_id": key_id,
                            "project_id": self.project_id,
                        }),
                        evidence={"sa_email": sa_email, "key_id": key_id, "age_days": age_days},
                    ))

        return findings
