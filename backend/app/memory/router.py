import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db
from app.memory.schemas import MemoryAnalysisResponse
from app.memory.models import MemoryAnalysisResult
from app.memory.service import memory_service

router = APIRouter(prefix="/memory", tags=["Memory Analysis"])

@router.post("/{sample_id}", response_model=MemoryAnalysisResponse)
async def trigger_memory_analysis(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Manually trigger memory analysis for a sample."""
    try:
        result = await memory_service.run_memory_analysis(str(sample_id), db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/{sample_id}", response_model=MemoryAnalysisResponse)
async def get_memory_analysis(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve memory analysis results for a sample."""
    result = await db.execute(
        select(MemoryAnalysisResult).where(MemoryAnalysisResult.sample_id == sample_id)
    )
    analysis = result.scalars().first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Memory analysis results not found")
        
    return analysis
