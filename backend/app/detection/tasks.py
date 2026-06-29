# MAP — Detection Tasks
# Celery tasks for detection rule processing.

import asyncio
from uuid import UUID

import structlog
from celery import shared_task

from app.core.database import async_session_factory
from app.detection.service import detection_service
from app.samples.models import Sample

logger = structlog.get_logger()

async def _generate_rules_async(sample_id_str: str) -> None:
    try:
        sample_id = UUID(sample_id_str)
        async with async_session_factory() as db:
            from sqlalchemy import select
            result = await db.execute(select(Sample).where(Sample.id == sample_id))
            sample = result.scalar_one_or_none()
            
            if sample:
                logger.info("Generating rules asynchronously", sample_id=sample_id_str)
                rules = await detection_service.generate_rules(db, sample)
                
                # Auto-validate YARA rules
                for rule in rules:
                    if rule.rule_type == "yara":
                        await detection_service.validate_rule(db, rule)
                        
    except Exception as e:
        logger.exception("Failed background rule generation", error=str(e))

@shared_task(name="app.detection.tasks.generate_rules")
def generate_rules_task(sample_id: str) -> None:
    """Background task to generate and validate rules."""
    asyncio.run(_generate_rules_async(sample_id))
