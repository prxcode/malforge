from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class ScanResponse(BaseModel):
    sample_id: str
    sha256: str
    risk_score: float
    classification: str
    static_analysis: Dict[str, Any]
    iocs: List[Dict[str, Any]]
    yara_matches: List[str]

class MemoryScanResponse(BaseModel):
    sample_id: str
    status: str
    processes: List[Dict[str, Any]]
    injected_processes: List[str]

class IocExtractRequest(BaseModel):
    text: str

class IocExtractResponse(BaseModel):
    ips: List[str]
    domains: List[str]
    urls: List[str]
    hashes: List[str]

class DetectionMatchRequest(BaseModel):
    sample_id: str

class DetectionMatchResponse(BaseModel):
    matches: List[str]

class GenerateRuleRequest(BaseModel):
    sample_id: str

class GenerateRuleResponse(BaseModel):
    yara_rule: str
    sigma_rule: Optional[str]
