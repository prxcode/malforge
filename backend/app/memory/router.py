# MAP — Memory Analysis Router
# FastAPI endpoints for memory forensics.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_authenticated_user, get_db
from app.memory.schemas import MemoryAnalysisResponse
from app.memory.service import memory_service
from app.memory.tasks import run_memory_analysis
from app.samples.service import sample_service

router = APIRouter(prefix="/analysis/memory", tags=["Memory Forensics"])


@router.post("/{sample_id}", status_code=status.HTTP_202_ACCEPTED)
async def trigger_memory_analysis(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Trigger memory forensics analysis for a memory dump sample."""
    sample = await sample_service.get_sample_by_id(db, sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    if sample.file_type != "memory_dump":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sample is not a memory dump"
        )

    run_memory_analysis.delay(str(sample.id))
    return {"message": "Memory analysis task queued", "sample_id": sample_id}


@router.get("/{sample_id}", response_model=MemoryAnalysisResponse)
async def get_memory_analysis(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Get memory analysis results for a sample."""
    result = await memory_service.get_analysis_by_sample_id(db, sample_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Memory analysis results not found. Analysis may still be pending."
        )
    return result
