import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SampleBase(BaseModel):
    filename: str
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    file_type: Optional[str] = None
    mime_type: Optional[str] = None
    size: int
    status: str


class SampleCreate(SampleBase):
    pass


class SampleResponse(SampleBase):
    id: uuid.UUID
    upload_time: datetime

    class Config:
        from_attributes = True


class SampleListResponse(BaseModel):
    items: list[SampleResponse]
    total: int
    page: int
    size: int
