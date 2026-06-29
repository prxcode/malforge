import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.service import analysis_service
from app.core.database import get_async_session
from app.detection.service import detection_service
from app.ioc.service import ioc_service
from app.memory.service import memory_service
from app.orchestrator.schemas import (
    DetectionMatchRequest,
    DetectionMatchResponse,
    GenerateRuleRequest,
    GenerateRuleResponse,
    IocExtractRequest,
    IocExtractResponse,
    MemoryScanResponse,
    ScanResponse,
)
from app.reports.service import report_service
from app.samples.service import sample_service

router = APIRouter(tags=["Orchestration"])


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...), db: AsyncSession = Depends(get_async_session)):
    # 1. Upload & Store
    file_data = await file.read()
    sample, _ = await sample_service.process_upload(
        db=db, file_data=file_data, filename=file.filename or "unknown", uploaded_by="system"
    )

    # 2. Static Analysis
    analysis_res = await analysis_service.run_static_analysis(str(sample.id), db)

    # 3. Extract IOCs
    iocs = await ioc_service.extract_and_store_iocs(str(sample.id), db)

    # 4. YARA Matches (Mocked via analysis heuristics for now as an example)
    yara_matches = (
        ["Suspicious_Packer", "Suspicious_Imports"] if analysis_res.heuristic_flags else []
    )

    # Calculate simple risk score
    risk_score = 0.0
    if analysis_res.heuristic_flags:
        risk_score += len(analysis_res.heuristic_flags) * 15.0
    if iocs:
        risk_score += len(iocs) * 5.0

    risk_score = min(100.0, risk_score)
    classification = (
        "MALICIOUS" if risk_score > 60 else "SUSPICIOUS" if risk_score > 30 else "BENIGN"
    )

    return ScanResponse(
        sample_id=str(sample.id),
        sha256=sample.sha256,
        risk_score=risk_score,
        classification=classification,
        static_analysis={
            "headers": analysis_res.headers,
            "sections": analysis_res.sections,
            "heuristics": analysis_res.heuristic_flags,
        },
        iocs=[{"type": ioc.indicator_type, "value": ioc.value} for ioc in iocs],
        yara_matches=yara_matches,
    )


@router.post("/scan/memory", response_model=MemoryScanResponse)
async def scan_memory(file: UploadFile = File(...), db: AsyncSession = Depends(get_async_session)):
    # Upload first
    file_data = await file.read()
    sample, _ = await sample_service.process_upload(
        db=db, file_data=file_data, filename=file.filename or "unknown", uploaded_by="system"
    )
    # Analyze memory
    mem_res = await memory_service.run_memory_analysis(str(sample.id), db)

    return MemoryScanResponse(
        sample_id=str(sample.id),
        status="completed",
        processes=mem_res.processes,
        injected_processes=mem_res.injected_processes,
    )


@router.post("/ioc/extract", response_model=IocExtractResponse)
async def extract_iocs(req: IocExtractRequest):
    # Dummy mock for direct extraction route from arbitrary text
    return IocExtractResponse(
        ips=["192.168.1.1"],
        domains=["malicious.com"],
        urls=["http://malicious.com/payload.exe"],
        hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )


@router.post("/detection/match", response_model=DetectionMatchResponse)
async def detection_match(req: DetectionMatchRequest):
    return DetectionMatchResponse(matches=["Ransomware_Behavior", "Obfuscated_API"])


@router.post("/detection/generate-rule", response_model=GenerateRuleResponse)
async def generate_rule(req: GenerateRuleRequest, db: AsyncSession = Depends(get_async_session)):
    sample_uuid = uuid.UUID(req.sample_id)
    rules = await detection_service.generate_rules(db, sample_uuid)

    yara_rule = ""
    sigma_rule = ""
    for r in rules:
        if r.rule_type.value == "yara":
            yara_rule = r.rule_text
        elif r.rule_type.value == "sigma":
            sigma_rule = r.rule_text

    return GenerateRuleResponse(yara_rule=yara_rule, sigma_rule=sigma_rule)


@router.get("/report/{file_hash}")
async def get_report(file_hash: str, db: AsyncSession = Depends(get_async_session)):
    sample = await sample_service.get_by_hash(db, file_hash)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    report = await report_service.generate_report(str(sample.id), db)
    return report
