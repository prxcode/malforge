# MAP — Memory Schemas
# Pydantic models for memory forensics analysis.

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class MemoryAnalysisResponse(BaseModel):
    """Full memory analysis response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID
    
    os_profile: Optional[str] = None
    analysis_status: str
    error_message: Optional[str] = None
    
    processes: List[Dict[str, Any]] = []
    process_tree: Dict[str, Any] = {}
    modules: List[Dict[str, Any]] = []
    registry: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    network_connections: List[Dict[str, Any]] = []
    handles: List[Dict[str, Any]] = []
    command_history: List[Dict[str, Any]] = []
    injected_memory: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []
    
    created_at: datetime
    updated_at: datetime
