# MAP — Static Analysis Schemas
# Pydantic models for static analysis requests and responses.

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class StaticAnalysisResponse(BaseModel):
    """Full static analysis response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sample_id: UUID
    
    headers: Dict[str, Any]
    sections: List[Dict[str, Any]]
    imports: List[Dict[str, Any]]
    exports: List[str]
    resources: List[Dict[str, Any]]
    
    strings: Dict[str, List[str]]
    
    compiler: Optional[str] = None
    entropy_score: Optional[float] = None
    suspicious_apis: List[str]
    heuristic_flags: List[Dict[str, Any]]
    heuristic_score: float
    
    entry_point: Optional[str] = None
    image_base: Optional[str] = None
    timestamp: Optional[str] = None
    
    created_at: datetime
    updated_at: datetime
