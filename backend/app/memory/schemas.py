import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class MemoryAnalysisBase(BaseModel):
    processes: List[Dict[str, Any]] = []
    modules: List[Dict[str, Any]] = []
    network_connections: List[Dict[str, Any]] = []
    registry_keys: List[Dict[str, Any]] = []
    injected_memory: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []

class MemoryAnalysisCreate(MemoryAnalysisBase):
    sample_id: uuid.UUID

class MemoryAnalysisResponse(MemoryAnalysisBase):
    id: uuid.UUID
    sample_id: uuid.UUID
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True
