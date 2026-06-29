# MAP — IOC Router
# FastAPI endpoints for IOC management.

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_authenticated_user, get_db
from app.ioc.models import IndicatorType
from app.ioc.schemas import IOCListResponse
from app.ioc.service import ioc_service

router = APIRouter(prefix="/ioc", tags=["Indicators of Compromise"])


@router.get("/sample/{sample_id}", response_model=IOCListResponse)
async def get_sample_iocs(
    sample_id: UUID,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Get all IOCs extracted for a specific sample."""
    skip = (page - 1) * size
    items, total = await ioc_service.list_iocs_for_sample(db, sample_id, skip=skip, limit=size)

    return IOCListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
    )


@router.get("/search", response_model=IOCListResponse)
async def search_iocs(
    indicator_type: IndicatorType | None = None,
    q: str | None = Query(None, min_length=3),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Search the global IOC database."""
    skip = (page - 1) * size
    items, total = await ioc_service.search_iocs(
        db, indicator_type=indicator_type, query_str=q, skip=skip, limit=size
    )

    return IOCListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
    )
