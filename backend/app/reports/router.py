# MAP — Threat Report Router
# FastAPI endpoints for threat reports.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_authenticated_user, get_db
from app.reports.schemas import ThreatReportListResponse, ThreatReportResponse
from app.reports.service import report_service
from app.samples.models import Sample

router = APIRouter(prefix="/reports", tags=["Threat Reports"])


@router.get("/sample/{sample_id}", response_model=ThreatReportResponse)
async def get_report_for_sample(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Get the threat report generated for a specific sample."""
    report = await report_service.get_report_by_sample_id(db, sample_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Threat report not found. It may not have been generated yet."
        )
    return report


@router.post("/generate/{sample_id}", response_model=ThreatReportResponse)
async def generate_report(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Manually trigger generation of a threat report for a sample."""
    result = await db.execute(select(Sample).where(Sample.id == sample_id))
    sample = result.scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    report = await report_service.generate_report(db, sample)
    return report


@router.get("", response_model=ThreatReportListResponse)
async def list_reports(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """List all threat reports."""
    skip = (page - 1) * size
    items, total = await report_service.list_reports(db, skip=skip, limit=size)

    return ThreatReportListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
    )
