"""Pydantic schemas for repositories, scans, and vulnerabilities.

Behaviour preserved verbatim from server.py — including the `extra="ignore"`
config and the field validators that coerce list-shaped scanner output to
scalars. Do not change these without a migration: stored Mongo documents
rely on this exact shape.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Repository(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    url: str
    access_token: str | None = None
    branch: str = "main"
    last_scan: str | None = None
    scan_status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    security_score: int | None = None
    vulnerabilities_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    provider: str | None = None
    full_name: str | None = None


class RepositoryCreate(BaseModel):
    name: str
    url: str
    access_token: str
    branch: str = "main"


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_id: str
    scan_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    category: str
    owasp_category: str
    title: str
    description: str
    code_snippet: str | None = ""
    cwe: str | None = None
    cvss_score: float | None = None
    fix_recommendation: str | None = None
    detected_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("cwe", mode="before")
    @classmethod
    def normalize_cwe(cls, v):
        if isinstance(v, list):
            return v[0] if v else None
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v):
        if isinstance(v, list):
            return v[0] if v else "medium"
        return v

    @field_validator("file_path", mode="before")
    @classmethod
    def normalize_file_path(cls, v):
        if isinstance(v, list):
            return v[0] if v else ""
        return v


class Scan(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_id: str
    status: str = "pending"
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    total_files: int = 0
    vulnerabilities_count: int = 0
    quality_issues_count: int = 0
    compliance_issues_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_score: int = 0
    quality_score: int = 100
    compliance_score: int = 100
    scan_results: dict[str, Any] = Field(default_factory=dict)


class AIFixRequest(BaseModel):
    vulnerability_id: str
    provider: str = "anthropic"
    # Resolved against llm.model_registry — None means "use the
    # provider's current default".
    model: str | None = None


class ReportRequest(BaseModel):
    repo_id: str
    scan_id: str
    format: str = "json"
