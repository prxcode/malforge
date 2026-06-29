import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class ThreatReportBase(BaseModel):
    executive_summary: Optional[str] = None
    file_metadata: Dict[str, Any] = {}
    malware_characteristics: Dict[str, Any] = {}
    attack_mapping: List[Dict[str, str]] = []
    observed_indicators: List[Dict[str, str]] = []
    detection_opportunities: List[Dict[str, str]] = []
    recommendations: List[str] = []
    rule_references: List[str] = []
    ioc_summary: Dict[str, int] = {}
    confidence_level: str = "medium"

class ThreatReportCreate(ThreatReportBase):
    sample_id: uuid.UUID

class ThreatReportResponse(ThreatReportBase):
    id: uuid.UUID
    sample_id: uuid.UUID

    class Config:
        from_attributes = True
