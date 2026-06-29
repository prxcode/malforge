import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db
from app.samples.models import Sample
from app.samples.schemas import SampleListResponse, SampleResponse
from app.samples.service import sample_service

router = APIRouter(prefix="/samples", tags=["Samples"])


@router.post("/", response_model=SampleResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    """Upload a new malware sample for analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing")
        
    try:
        sample = await sample_service.process_upload(file, db)
        return sample
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/", response_model=SampleListResponse)
async def list_samples(
    skip: int = 0, 
    limit: int = 20, 
    db: AsyncSession = Depends(get_db)
):
    """List all samples with pagination."""
    # Count total
    from sqlalchemy import func
    total_result = await db.execute(select(func.count(Sample.id)))
    total = total_result.scalar_one()
    
    # Get items
    result = await db.execute(select(Sample).offset(skip).limit(limit))
    items = result.scalars().all()
    
    return {
        "items": items,
        "total": total,
        "page": skip // limit + 1 if limit > 0 else 1,
        "size": limit
    }


@router.get("/{sample_id}", response_model=SampleResponse)
async def get_sample(
    sample_id: uuid.UUID, 
    db: AsyncSession = Depends(get_db)
):
    """Get details of a specific sample."""
    result = await db.execute(select(Sample).where(Sample.id == sample_id))
    sample = result.scalars().first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
        
    return sample
