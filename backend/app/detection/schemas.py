import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

class DetectionRuleBase(BaseModel):
    rule_type: str
    rule_name: str
    version: int
    rule_text: str

class DetectionRuleCreate(DetectionRuleBase):
    sample_id: uuid.UUID

class DetectionRuleResponse(DetectionRuleBase):
    id: uuid.UUID
    sample_id: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True

class DetectionRuleListResponse(BaseModel):
    items: list[DetectionRuleResponse]
    total: int
