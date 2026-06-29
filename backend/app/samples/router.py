# MAP — Sample Router
# FastAPI endpoints for sample management.

from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.dependencies import get_authenticated_user, get_db
from app.samples.models import SampleStatus
from app.samples.schemas import SampleListResponse, SampleResponse, SampleUpdate
from app.samples.service import sample_service

# We will import the celery task once it's created
# from app.analysis.tasks import run_static_analysis

router = APIRouter(prefix="/samples", tags=["Samples"])
settings = get_settings()


@router.post("", response_model=SampleResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    tags: str | None = Form(None),
    notes: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """
    Upload a new malware sample or memory image.
    Automatically triggers static analysis for executable files.
    """
    if file.size and file.size > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {settings.max_upload_size_mb}MB",
        )

    file_data = await file.read()

    sample, created = await sample_service.process_upload(
        db=db,
        file_data=file_data,
        filename=file.filename or "unknown",
        uploaded_by=current_user["username"],
        tags=tags,
        notes=notes,
    )

    if not created:
        return sample

    # Trigger analysis task asynchronously if it's a PE file
    if sample.file_type in ["pe_exe", "pe_dll"]:
        from app.analysis.tasks import run_static_analysis

        # Mark as analyzing
        sample.status = SampleStatus.ANALYZING
        await db.commit()

        # Trigger celery task
        run_static_analysis.delay(str(sample.id))

    return sample


@router.get("", response_model=SampleListResponse)
async def list_samples(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: SampleStatus | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """List uploaded samples with pagination."""
    skip = (page - 1) * size
    items, total = await sample_service.list_samples(db, skip=skip, limit=size, status=status)

    return SampleListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
    )


@router.get("/{sample_id}", response_model=SampleResponse)
async def get_sample(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Get sample details by ID."""
    sample = await sample_service.get_sample_by_id(db, sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    return sample


@router.patch("/{sample_id}", response_model=SampleResponse)
async def update_sample(
    sample_id: UUID,
    update_data: SampleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Update sample metadata (tags, notes)."""
    sample = await sample_service.get_sample_by_id(db, sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    return await sample_service.update_sample(db, sample, update_data)


@router.delete("/{sample_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sample(
    sample_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_authenticated_user),
):
    """Delete a sample and its associated files."""
    # Ensure role is high enough
    if current_user["role"] not in ["admin", "engineer"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to delete samples"
        )

    sample = await sample_service.get_sample_by_id(db, sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    await sample_service.delete_sample(db, sample)
