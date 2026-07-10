from abc import ABC, abstractmethod
from typing import List
import logging

from googleapiclient.discovery import build
from googleapiclient import errors as google_errors
import google.auth

from scanner.findings import Finding


logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    def __init__(self, project_id: str, credentials=None):
        self.project_id = project_id
        self.credentials = credentials
        self._compute_client = None
        self._iam_client = None
        self._crm_client = None
        self._logging_client = None
        self._sqladmin_client = None

    @property
    def compute(self):
        if not self._compute_client:
            self._compute_client = build(
                "compute", "v1", credentials=self.credentials, cache_discovery=False
            )
        return self._compute_client

    @property
    def iam(self):
        if not self._iam_client:
            self._iam_client = build(
                "iam", "v1", credentials=self.credentials, cache_discovery=False
            )
        return self._iam_client

    @property
    def crm(self):
        if not self._crm_client:
            self._crm_client = build(
                "cloudresourcemanager", "v1", credentials=self.credentials, cache_discovery=False
            )
        return self._crm_client

    @property
    def logging_svc(self):
        if not self._logging_client:
            self._logging_client = build(
                "logging", "v2", credentials=self.credentials, cache_discovery=False
            )
        return self._logging_client

    @property
    def sqladmin(self):
        if not self._sqladmin_client:
            self._sqladmin_client = build(
                "sqladmin", "v1", credentials=self.credentials, cache_discovery=False
            )
        return self._sqladmin_client

    @abstractmethod
    def scan(self) -> List[Finding]:
        pass
