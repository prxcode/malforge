# MAP — Detection Router
# FastAPI endpoints for detection engineering.

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_authenticated_user, get_db
from app.detection.models import DetectionRule
from app.detection.schemas import (
    DetectionRuleListResponse,
    DetectionRuleResponse,
    ValidationResultResponse,
)
from app.detection.service import detection_service
from app.samples.models import Sample

router = APIRouter(prefix="/rules", tags=["Detection Engineering"])


@router.get("/sample/{sample_id}", response_model=DetectionRuleListResponse)
async def get_rules_for_sample(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Get all detection rules generated for a specific sample."""
    items, total = await detection_service.list_rules_for_sample(db, sample_id)

    return DetectionRuleListResponse(
        items=items,
        total=total,
    )


@router.post("/generate/{sample_id}", response_model=list[DetectionRuleResponse])
async def generate_rules(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Manually trigger generation of detection rules for a sample."""
    result = await db.execute(select(Sample).where(Sample.id == sample_id))
    sample = result.scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    rules = await detection_service.generate_rules(db, sample)
    return rules


@router.post("/validate/{rule_id}", response_model=ValidationResultResponse)
async def validate_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Run validation testing on a specific rule."""
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    val_result = await detection_service.validate_rule(db, rule)

    if not val_result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Validation failed or not supported for this rule type",
        )

    return val_result
