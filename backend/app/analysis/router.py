import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db
from app.analysis.schemas import StaticAnalysisResponse
from app.analysis.models import StaticAnalysisResult
from app.analysis.service import analysis_service
from app.samples.models import Sample

router = APIRouter(prefix="/analysis", tags=["Analysis"])

@router.post("/static/{sample_id}", response_model=StaticAnalysisResponse)
async def trigger_static_analysis(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Manually trigger static analysis for a sample."""
    try:
        # In a real app this would trigger a Celery task.
        # For simplicity in this iteration, we run it synchronously.
        result = await analysis_service.run_static_analysis(str(sample_id), db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/static/{sample_id}", response_model=StaticAnalysisResponse)
async def get_static_analysis(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve static analysis results for a sample."""
    result = await db.execute(
        select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample_id)
    )
    analysis = result.scalars().first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis results not found")
        
    return analysis
