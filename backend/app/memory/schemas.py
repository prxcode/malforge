# MAP — Memory Schemas
# Pydantic models for memory forensics analysis.

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class MemoryAnalysisResponse(BaseModel):
    """Full memory analysis response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID

    os_profile: str | None = None
    analysis_status: str
    error_message: str | None = None

    processes: list[dict[str, Any]] = []
    process_tree: dict[str, Any] = {}
    modules: list[dict[str, Any]] = []
    registry: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    network_connections: list[dict[str, Any]] = []
    handles: list[dict[str, Any]] = []
    command_history: list[dict[str, Any]] = []
    injected_memory: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []

    created_at: datetime
    updated_at: datetime
