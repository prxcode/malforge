# MAP — Memory Analysis Tasks
# Celery background tasks for long-running memory forensics.

import asyncio
from uuid import UUID

import structlog
from celery import shared_task

from app.core.database import async_session_factory
from app.memory.service import memory_service
from app.samples.models import Sample, SampleStatus

logger = structlog.get_logger()


async def _run_memory_analysis_async(sample_id_str: str) -> None:
    """Async wrapper for running memory analysis."""
    try:
        sample_id = UUID(sample_id_str)
        async with async_session_factory() as db:
            from sqlalchemy import select
            result = await db.execute(select(Sample).where(Sample.id == sample_id))
            sample = result.scalar_one_or_none()

            if not sample:
                logger.error("Sample not found for memory analysis", sample_id=sample_id_str)
                return

            logger.info("Starting memory analysis", sample_id=sample_id_str)

            try:
                await memory_service.run_analysis(db, sample)
                logger.info("Completed memory analysis", sample_id=sample_id_str)
            except Exception as e:
                logger.exception("Memory analysis failed", sample_id=sample_id_str, error=str(e))
                sample.status = SampleStatus.FAILED
                await db.commit()

    except Exception as e:
        logger.exception("Failed in async memory analysis wrapper", error=str(e))


@shared_task(name="app.memory.tasks.run_memory_analysis")
def run_memory_analysis(sample_id: str) -> None:
    """Celery task to run memory analysis on a memory dump."""
    asyncio.run(_run_memory_analysis_async(sample_id))
