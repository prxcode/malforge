import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db
from app.reports.schemas import ThreatReportResponse
from app.reports.models import ThreatReport
from app.reports.service import report_service

router = APIRouter(prefix="/reports", tags=["Threat Reports"])

@router.post("/generate/{sample_id}", response_model=ThreatReportResponse)
async def generate_threat_report(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Generate a comprehensive threat report for a sample."""
    try:
        report = await report_service.generate_report(str(sample_id), db)
        return report
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@router.get("/{sample_id}", response_model=ThreatReportResponse)
async def get_threat_report(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve the generated threat report for a sample."""
    result = await db.execute(
        select(ThreatReport).where(ThreatReport.sample_id == sample_id)
    )
    report = result.scalars().first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    return report
