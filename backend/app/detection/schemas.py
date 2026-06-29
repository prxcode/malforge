# MAP — Detection Schemas
# Pydantic models for detection rule requests and responses.

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.detection.models import RuleType


class ValidationResultResponse(BaseModel):
    """Validation metrics for a rule."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: UUID
    true_positive_rate: Optional[float] = None
    false_positive_rate: Optional[float] = None
    coverage: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    score: Optional[float] = None
    test_samples_count: int
    matches_count: int
    details: Dict[str, Any]
    created_at: datetime


class DetectionRuleResponse(BaseModel):
    """Full detection rule response."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID
    rule_type: RuleType
    rule_name: str
    version: int
    rule_text: str
    metadata: Dict[str, Any]
    
    validation_results: List[ValidationResultResponse] = []
    
    created_at: datetime
    updated_at: datetime


class DetectionRuleListResponse(BaseModel):
    """List of detection rules."""

    items: List[DetectionRuleResponse]
    total: int
