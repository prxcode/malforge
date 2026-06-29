# MAP — Static Analysis Tasks
# Celery background tasks for long-running analysis.

import asyncio
from uuid import UUID

import structlog
from celery import shared_task

from app.analysis.service import analysis_service
from app.core.database import async_session_factory
from app.samples.models import Sample, SampleStatus

logger = structlog.get_logger()


async def _run_analysis_async(sample_id_str: str) -> None:
    """Async wrapper for running static analysis."""
    try:
        sample_id = UUID(sample_id_str)
        async with async_session_factory() as db:
            # Get sample
            from sqlalchemy import select

            result = await db.execute(select(Sample).where(Sample.id == sample_id))
            sample = result.scalar_one_or_none()

            if not sample:
                logger.error("Sample not found for analysis", sample_id=str(sample_id))
                return

            logger.info("Starting static analysis", sample_id=str(sample_id))

            try:
                await analysis_service.run_analysis(db, sample)
                logger.info("Completed static analysis", sample_id=str(sample_id))
            except Exception as e:
                logger.exception("Analysis failed", sample_id=str(sample_id), error=str(e))
                sample.status = SampleStatus.FAILED
                await db.commit()

    except Exception as e:
        logger.exception("Failed in async analysis wrapper", error=str(e))


@shared_task(name="app.analysis.tasks.run_static_analysis")
def run_static_analysis(sample_id: str) -> None:
    """Celery task to run static analysis on a sample."""
    asyncio.run(_run_analysis_async(sample_id))
