import logging
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

from scanner.findings import ScanResult


logger = logging.getLogger(__name__)


class ELKShipper:
    def __init__(
        self,
        host: str,
        index: str = "gcp-misconfig-findings",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.host = host.rstrip("/")
        self.index = index
        self.auth = HTTPBasicAuth(username, password) if username and password else None

    def ship(self, result: ScanResult) -> int:
        shipped = 0
        for finding in result.findings:
            doc = self._to_ecs_document(finding, result.project_id)
            try:
                resp = requests.post(
                    f"{self.host}/{self.index}/_doc",
                    json=doc,
                    auth=self.auth,
                    timeout=10,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                shipped += 1
            except requests.RequestException as exc:
                logger.warning("Failed to ship finding %s: %s", finding.rule_id, exc)

        logger.info("Shipped %d/%d findings to ELK", shipped, len(result.findings))
        return shipped

    def _to_ecs_document(self, finding, project_id: str) -> dict:
        return {
            "@timestamp": finding.timestamp,
            "event": {
                "kind": "finding",
                "category": ["configuration"],
                "type": ["info"],
                "severity": self._severity_to_int(finding.severity.value),
                "dataset": "gcp.misconfig",
                "module": "gcp-misconfig-scanner",
                "outcome": "failure",
            },
            "rule": {
                "id": finding.rule_id,
                "name": finding.title,
                "description": finding.description,
                "reference": finding.cis_benchmark or "",
            },
            "cloud": {
                "provider": "gcp",
                "project": {"id": project_id},
                "resource": {
                    "type": finding.resource_type,
                    "name": finding.resource_name,
                },
            },
            "vulnerability": {
                "severity": finding.severity.value,
                "category": ["misconfiguration"],
                "description": finding.description,
            },
            "gcp_misconfig": {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "resource_type": finding.resource_type,
                "resource_name": finding.resource_name,
                "cis_benchmark": finding.cis_benchmark,
                "remediation": finding.remediation_steps,
                "has_terraform_fix": bool(finding.terraform_fix),
                "evidence": finding.evidence or {},
            },
        }

    @staticmethod
    def _severity_to_int(severity: str) -> int:
        return {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 30, "INFO": 10}.get(severity, 0)
