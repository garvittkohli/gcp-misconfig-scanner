from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, List


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_name: str
    project_id: str
    remediation_steps: str
    cis_benchmark: Optional[str] = None
    terraform_fix: Optional[str] = None
    evidence: Optional[Dict] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "project_id": self.project_id,
            "remediation_steps": self.remediation_steps,
            "cis_benchmark": self.cis_benchmark,
            "terraform_fix": self.terraform_fix,
            "evidence": self.evidence or {},
            "timestamp": self.timestamp,
        }


class ScanResult:
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.findings: List[Finding] = []
        self.scan_start = datetime.utcnow().isoformat() + "Z"
        self.scan_end: Optional[str] = None
        self.errors: List[str] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_error(self, message: str):
        self.errors.append(message)

    def finalize(self):
        self.scan_end = datetime.utcnow().isoformat() + "Z"

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])

    def summary(self) -> Dict:
        return {
            "project_id": self.project_id,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "total_findings": len(self.findings),
            "critical": len(self.by_severity(Severity.CRITICAL)),
            "high": len(self.by_severity(Severity.HIGH)),
            "medium": len(self.by_severity(Severity.MEDIUM)),
            "low": len(self.by_severity(Severity.LOW)),
            "info": len(self.by_severity(Severity.INFO)),
            "errors": self.errors,
        }
