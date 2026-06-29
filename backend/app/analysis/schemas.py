# MAP — Static Analysis Schemas
# Pydantic models for static analysis requests and responses.

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class StaticAnalysisResponse(BaseModel):
    """Full static analysis response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID

    headers: dict[str, Any]
    sections: list[dict[str, Any]]
    imports: list[dict[str, Any]]
    exports: list[str]
    resources: list[dict[str, Any]]

    strings: dict[str, list[str]]

    compiler: str | None = None
    entropy_score: float | None = None
    suspicious_apis: list[str]
    heuristic_flags: list[dict[str, Any]]
    heuristic_score: float

    entry_point: str | None = None
    image_base: str | None = None
    timestamp: str | None = None

    created_at: datetime
    updated_at: datetime
