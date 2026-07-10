import logging
from typing import List, Optional

import google.auth
from google.auth.exceptions import DefaultCredentialsError

from scanner.findings import ScanResult
from scanner.scanners.iam import IAMScanner
from scanner.scanners.compute import ComputeScanner
from scanner.scanners.firewall import FirewallScanner
from scanner.scanners.storage import StorageScanner
from scanner.scanners.sql import SQLScanner
from scanner.scanners.logging_mon import LoggingScanner


logger = logging.getLogger(__name__)

SCANNER_MAP = {
    "iam": IAMScanner,
    "compute": ComputeScanner,
    "firewall": FirewallScanner,
    "storage": StorageScanner,
    "sql": SQLScanner,
    "logging": LoggingScanner,
}


class ScanEngine:
    def __init__(
        self,
        project_id: str,
        skip_scanners: Optional[List[str]] = None,
        service_account_file: Optional[str] = None,
    ):
        self.project_id = project_id
        self.skip_scanners = [s.lower() for s in (skip_scanners or [])]
        self.credentials = self._load_credentials(service_account_file)

    def _load_credentials(self, sa_file: Optional[str]):
        if sa_file:
            from google.oauth2 import service_account
            return service_account.Credentials.from_service_account_file(
                sa_file,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        try:
            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            return credentials
        except DefaultCredentialsError as exc:
            raise RuntimeError(
                "No GCP credentials found. Run 'gcloud auth application-default login' "
                "or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file."
            ) from exc

    def run(self) -> ScanResult:
        result = ScanResult(project_id=self.project_id)
        logger.info("Starting scan of project: %s", self.project_id)

        for scanner_name, scanner_class in SCANNER_MAP.items():
            if scanner_name in self.skip_scanners:
                logger.info("Skipping scanner: %s", scanner_name)
                continue

            logger.info("Running %s scanner...", scanner_name)
            try:
                scanner = scanner_class(
                    project_id=self.project_id,
                    credentials=self.credentials,
                )
                findings = scanner.scan()
                for finding in findings:
                    result.add_finding(finding)
                logger.info("%s scanner: %d findings", scanner_name, len(findings))
            except Exception as exc:
                error_msg = f"Scanner '{scanner_name}' failed: {exc}"
                logger.error(error_msg)
                result.add_error(error_msg)

        result.finalize()
        logger.info("Scan complete. Total findings: %d", len(result.findings))
        return result
