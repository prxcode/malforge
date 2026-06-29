import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from pydantic import BaseModel


class StaticAnalysisBase(BaseModel):
    compiler: Optional[str] = None
    entropy_score: Optional[float] = None
    headers: Dict[str, Any] = {}
    sections: List[Dict[str, Any]] = []
    imports: Dict[str, List[str]] = {}
    exports: List[str] = []
    strings: Dict[str, Any] = {}
    suspicious_apis: List[str] = []
    heuristic_flags: List[Dict[str, str]] = []


class StaticAnalysisCreate(StaticAnalysisBase):
    sample_id: uuid.UUID


class StaticAnalysisResponse(StaticAnalysisBase):
    id: uuid.UUID
    sample_id: uuid.UUID
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True
