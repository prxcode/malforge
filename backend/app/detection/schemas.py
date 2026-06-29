# MAP — Detection Schemas
# Pydantic models for detection rule requests and responses.

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.detection.models import RuleType


class ValidationResultResponse(BaseModel):
    """Validation metrics for a rule."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: UUID
    true_positive_rate: float | None = None
    false_positive_rate: float | None = None
    coverage: float | None = None
    precision: float | None = None
    recall: float | None = None
    score: float | None = None
    test_samples_count: int
    matches_count: int
    details: dict[str, Any]
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
    metadata: dict[str, Any]

    validation_results: list[ValidationResultResponse] = []

    created_at: datetime
    updated_at: datetime


class DetectionRuleListResponse(BaseModel):
    """List of detection rules."""

    items: list[DetectionRuleResponse]
    total: int
