# MAP — IOC Schemas
# Pydantic models for IOC requests and responses.

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.ioc.models import IndicatorType


class IOCBase(BaseModel):
    """Base IOC schema."""

    indicator_type: IndicatorType
    value: str
    confidence: float
    source: Optional[str] = None
    context: Optional[str] = None


class IOCResponse(IOCBase):
    """Full IOC response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID
    created_at: datetime
    updated_at: datetime


class IOCListResponse(BaseModel):
    """Paginated list of IOCs."""

    items: list[IOCResponse]
    total: int
    page: int
    size: int
