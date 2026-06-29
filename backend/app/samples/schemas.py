# MAP — Sample Schemas
# Pydantic models for sample requests and responses.

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.samples.models import FileType, SampleStatus


class SampleBase(BaseModel):
    """Base sample schema."""

    filename: str = Field(..., description="Original filename")
    tags: Optional[str] = Field(None, description="JSON array of tags as string")
    notes: Optional[str] = Field(None, description="Analyst notes")


class SampleCreate(SampleBase):
    """Schema for sample creation (usually handled via form data during upload)."""
    pass


class SampleUpdate(BaseModel):
    """Schema for updating a sample."""

    tags: Optional[str] = None
    notes: Optional[str] = None


class SampleResponse(SampleBase):
    """Full sample response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sha256: str
    sha1: str
    md5: str
    file_size: int
    entropy: Optional[float] = None
    file_type: FileType
    mime_type: Optional[str] = None
    compiler_info: Optional[str] = None
    signature_status: Optional[str] = None
    status: SampleStatus
    uploaded_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class SampleListResponse(BaseModel):
    """Paginated list of samples."""

    items: list[SampleResponse]
    total: int
    page: int
    size: int
