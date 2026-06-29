from typing import Any

from pydantic import BaseModel


class ScanResponse(BaseModel):
    sample_id: str
    sha256: str
    risk_score: float
    classification: str
    static_analysis: dict[str, Any]
    iocs: list[dict[str, Any]]
    yara_matches: list[str]

class MemoryScanResponse(BaseModel):
    sample_id: str
    status: str
    processes: list[dict[str, Any]]
    injected_processes: list[str]

class IocExtractRequest(BaseModel):
    text: str

class IocExtractResponse(BaseModel):
    ips: list[str]
    domains: list[str]
    urls: list[str]
    hashes: list[str]

class DetectionMatchRequest(BaseModel):
    sample_id: str

class DetectionMatchResponse(BaseModel):
    matches: list[str]

class GenerateRuleRequest(BaseModel):
    sample_id: str

class GenerateRuleResponse(BaseModel):
    yara_rule: str
    sigma_rule: str | None
