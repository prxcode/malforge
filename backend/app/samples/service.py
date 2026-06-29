# MAP — Sample Service
# Business logic for processing malware samples.

from uuid import UUID

import magic
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.storage import storage_service
from app.samples.models import FileType, Sample, SampleStatus
from app.samples.schemas import SampleUpdate


class SampleService:
    """Service for managing malware samples."""

    async def get_sample_by_id(self, db: AsyncSession, sample_id: UUID) -> Sample | None:
        """Retrieve a sample by its UUID."""
        result = await db.execute(select(Sample).where(Sample.id == sample_id))
        return result.scalar_one_or_none()

    async def get_sample_by_hash(self, db: AsyncSession, sha256: str) -> Sample | None:
        """Retrieve a sample by its SHA256 hash."""
        result = await db.execute(select(Sample).where(Sample.sha256 == sha256))
        return result.scalar_one_or_none()

    async def list_samples(
        self, db: AsyncSession, skip: int = 0, limit: int = 20, status: SampleStatus | None = None
    ) -> tuple[list[Sample], int]:
        """List samples with optional filtering."""
        query = select(Sample)
        if status:
            query = query.where(Sample.status == status)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        # Get paginated items
        query = query.order_by(Sample.created_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        items = list(result.scalars().all())

        return items, total

    async def process_upload(
        self,
        db: AsyncSession,
        file_data: bytes,
        filename: str,
        uploaded_by: str | None = None,
        tags: str | None = None,
        notes: str | None = None,
    ) -> tuple[Sample, bool]:
        """
        Process an uploaded file, compute hashes, save to storage, and create DB record.
        Returns the sample and a boolean indicating if it was newly created.
        """
        hashes = storage_service.compute_hashes(file_data)
        sha256 = hashes["sha256"]

        # Check for duplicates
        existing = await self.get_sample_by_hash(db, sha256)
        if existing:
            return existing, False

        # File type detection
        mime_type = magic.from_buffer(file_data, mime=True)
        file_type = self._determine_file_type(file_data, mime_type, filename)

        # Entropy calculation
        entropy = storage_service.compute_entropy(file_data)

        # Save to storage
        storage_path = await storage_service.save_file(
            file_data=file_data,
            sha256=sha256,
            filename=filename,
            content_type=mime_type,
        )

        # Create DB record
        sample = Sample(
            filename=filename,
            sha256=sha256,
            sha1=hashes["sha1"],
            md5=hashes["md5"],
            file_size=len(file_data),
            entropy=entropy,
            file_type=file_type,
            mime_type=mime_type,
            status=SampleStatus.PENDING,
            storage_path=storage_path,
            uploaded_by=uploaded_by,
            tags=tags,
            notes=notes,
        )
        db.add(sample)
        await db.commit()
        await db.refresh(sample)

        return sample, True

    def _determine_file_type(self, data: bytes, mime_type: str, filename: str) -> FileType:
        """Determine the file type based on magic bytes and MIME type."""
        filename_lower = filename.lower()

        if data.startswith(b"MZ"):
            if filename_lower.endswith(".dll"):
                return FileType.PE_DLL
            return FileType.PE_EXE
        elif data.startswith(b"\x7fELF"):
            return FileType.ELF
        elif data.startswith(b"PK\x03\x04"):
            return FileType.ZIP_ARCHIVE
        elif "application/x-dmp" in mime_type or filename_lower.endswith((".dmp", ".vmem", ".raw")):
            return FileType.MEMORY_DUMP

        return FileType.UNKNOWN

    async def update_sample(
        self, db: AsyncSession, sample: Sample, update_data: SampleUpdate
    ) -> Sample:
        """Update sample metadata."""
        if update_data.tags is not None:
            sample.tags = update_data.tags
        if update_data.notes is not None:
            sample.notes = update_data.notes

        await db.commit()
        await db.refresh(sample)
        return sample

    async def delete_sample(self, db: AsyncSession, sample: Sample) -> None:
        """Delete sample from DB and storage."""
        # Note: In production you might want a soft delete, but we'll do hard delete here
        await storage_service.delete_file(sample.sha256, sample.filename)
        await db.delete(sample)
        await db.commit()


sample_service = SampleService()
