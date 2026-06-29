# MAP — IOC Service
# Business logic for managing Indicators of Compromise.

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ioc.extractors import IOCExtractor
from app.ioc.models import IndicatorType, IOCEntry


class IOCService:
    """Service for managing indicators of compromise."""

    def __init__(self):
        self.extractor = IOCExtractor()

    async def list_iocs_for_sample(
        self, db: AsyncSession, sample_id: UUID, skip: int = 0, limit: int = 100
    ) -> tuple[list[IOCEntry], int]:
        """List all IOCs associated with a specific sample."""
        query = select(IOCEntry).where(IOCEntry.sample_id == sample_id)

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        query = query.order_by(IOCEntry.confidence.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        items = list(result.scalars().all())

        return items, total

    async def search_iocs(
        self,
        db: AsyncSession,
        indicator_type: IndicatorType | None = None,
        query_str: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[IOCEntry], int]:
        """Search IOCs globally."""
        query = select(IOCEntry)

        if indicator_type:
            query = query.where(IOCEntry.indicator_type == indicator_type)

        if query_str:
            # Substring match
            query = query.where(IOCEntry.value.ilike(f"%{query_str}%"))

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar_one()

        query = query.order_by(IOCEntry.created_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        items = list(result.scalars().all())

        return items, total

    async def extract_and_store_from_strings(
        self, db: AsyncSession, sample_id: UUID, strings: list[str]
    ) -> list[IOCEntry]:
        """Extract IOCs from strings and store them in the database."""
        extracted_data = self.extractor.extract_from_strings(strings)

        # Remove old static_strings IOCs for this sample if re-running
        await db.execute(
            select(IOCEntry).where(
                IOCEntry.sample_id == sample_id, IOCEntry.source == "static_strings"
            )
        )
        # TODO: Implement proper deletion of old entries if needed

        entries = []
        for data in extracted_data:
            entry = IOCEntry(
                sample_id=sample_id,
                indicator_type=data["indicator_type"],
                value=data["value"],
                confidence=data["confidence"],
                source=data["source"],
                context=data["context"],
            )
            db.add(entry)
            entries.append(entry)

        await db.commit()
        return entries


ioc_service = IOCService()
