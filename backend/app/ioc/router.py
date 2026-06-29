import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db
from app.ioc.schemas import IOCListResponse
from app.ioc.models import IOCEntry
from app.ioc.service import ioc_service

router = APIRouter(prefix="/ioc", tags=["IOCs"])

@router.post("/{sample_id}", status_code=status.HTTP_201_CREATED)
async def generate_iocs(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Manually extract IOCs for a sample from its analysis results."""
    iocs = await ioc_service.extract_and_store_iocs(str(sample_id), db)
    return {"message": f"Extracted {len(iocs)} IOCs", "count": len(iocs)}

@router.get("/{sample_id}", response_model=IOCListResponse)
async def get_sample_iocs(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get all IOCs extracted from a specific sample."""
    from sqlalchemy import func
    
    # Count total
    total_result = await db.execute(
        select(func.count(IOCEntry.id)).where(IOCEntry.sample_id == sample_id)
    )
    total = total_result.scalar_one()
    
    # Get items
    result = await db.execute(
        select(IOCEntry).where(IOCEntry.sample_id == sample_id)
    )
    items = result.scalars().all()
    
    return {
        "items": items,
        "total": total
    }
