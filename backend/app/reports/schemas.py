# MAP — Threat Report Schemas
# Pydantic models for threat intelligence reports.

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ThreatReportResponse(BaseModel):
    """Full threat report response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID
    
    executive_summary: Optional[str] = None
    file_metadata: Dict[str, Any]
    malware_characteristics: Dict[str, Any]
    attack_mapping: List[Dict[str, Any]]
    observed_indicators: List[Dict[str, Any]]
    detection_opportunities: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    rule_references: List[Dict[str, Any]]
    ioc_summary: Dict[str, Any]
    
    confidence_level: str
    
    created_at: datetime
    updated_at: datetime


class ThreatReportListResponse(BaseModel):
    """List of threat reports."""

    items: List[ThreatReportResponse]
    total: int
    page: int
    size: int
