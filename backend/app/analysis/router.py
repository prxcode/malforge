# MAP — Static Analysis Router
# FastAPI endpoints for static analysis.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.schemas import StaticAnalysisResponse
from app.analysis.service import analysis_service
from app.analysis.tasks import run_static_analysis
from app.core.dependencies import get_authenticated_user, get_db
from app.samples.service import sample_service

router = APIRouter(prefix="/analysis/static", tags=["Analysis"])


@router.post("/{sample_id}", status_code=status.HTTP_202_ACCEPTED)
async def trigger_analysis(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Trigger static analysis for a sample."""
    sample = await sample_service.get_sample_by_id(db, sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    run_static_analysis.delay(str(sample.id))
    return {"message": "Static analysis task queued", "sample_id": sample_id}


@router.get("/{sample_id}", response_model=StaticAnalysisResponse)
async def get_analysis(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Get static analysis results for a sample."""
    result = await analysis_service.get_analysis_by_sample_id(db, sample_id)
    if not result:
        raise HTTPException(
            status_code=404, detail="Analysis results not found. Analysis may still be pending."
        )
    return result
