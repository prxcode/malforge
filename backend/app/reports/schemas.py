# MAP — Threat Report Schemas
# Pydantic models for threat intelligence reports.

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ThreatReportResponse(BaseModel):
    """Full threat report response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID

    executive_summary: str | None = None
    file_metadata: dict[str, Any]
    malware_characteristics: dict[str, Any]
    attack_mapping: list[dict[str, Any]]
    observed_indicators: list[dict[str, Any]]
    detection_opportunities: list[dict[str, Any]]
    recommendations: list[dict[str, Any]]
    rule_references: list[dict[str, Any]]
    ioc_summary: dict[str, Any]

    confidence_level: str

    created_at: datetime
    updated_at: datetime


class ThreatReportListResponse(BaseModel):
    """List of threat reports."""

    items: list[ThreatReportResponse]
    total: int
    page: int
    size: int
