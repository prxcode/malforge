import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

class IOCBase(BaseModel):
    indicator_type: str
    value: str
    confidence: str
    source: str
    context: Optional[str] = None

class IOCCreate(IOCBase):
    sample_id: uuid.UUID

class IOCResponse(IOCBase):
    id: uuid.UUID
    sample_id: uuid.UUID
    first_seen: datetime

    class Config:
        from_attributes = True

class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
