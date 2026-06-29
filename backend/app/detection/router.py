import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db
from app.detection.schemas import DetectionRuleListResponse
from app.detection.models import DetectionRule
from app.detection.service import detection_service

router = APIRouter(prefix="/rules", tags=["Detection Rules"])

@router.post("/generate/{sample_id}", status_code=status.HTTP_201_CREATED)
async def generate_rules_for_sample(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Generate YARA and Sigma rules for a sample."""
    try:
        rules = await detection_service.generate_rules(str(sample_id), db)
        return {"message": f"Generated {len(rules)} rules", "count": len(rules)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{sample_id}", response_model=DetectionRuleListResponse)
async def get_sample_rules(
    sample_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get all rules generated for a specific sample."""
    from sqlalchemy import func
    
    # Count total
    total_result = await db.execute(
        select(func.count(DetectionRule.id)).where(DetectionRule.sample_id == sample_id)
    )
    total = total_result.scalar_one()
    
    # Get items
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.sample_id == sample_id)
    )
    items = result.scalars().all()
    
    return {
        "items": items,
        "total": total
    }
