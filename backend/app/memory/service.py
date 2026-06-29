# MAP — Memory Analysis Service
# Orchestrates Volatility 3 execution on memory dumps.

from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.storage import storage_service
from app.memory.models import MemoryAnalysisResult
from app.memory.vol3_adapter import Volatility3Adapter
from app.samples.models import Sample, SampleStatus

logger = structlog.get_logger()


class MemoryAnalysisService:
    """Service for running memory forensics on samples."""

    async def get_analysis_by_sample_id(
        self, db: AsyncSession, sample_id: UUID
    ) -> MemoryAnalysisResult | None:
        """Retrieve memory analysis results for a sample."""
        result = await db.execute(
            select(MemoryAnalysisResult).where(MemoryAnalysisResult.sample_id == sample_id)
        )
        return result.scalar_one_or_none()

    async def run_analysis(self, db: AsyncSession, sample: Sample) -> MemoryAnalysisResult:
        """Run memory analysis on a memory dump file."""

        if sample.file_type != "memory_dump":
            raise ValueError(f"Sample {sample.id} is not a memory dump.")

        # Ensure we have the file available locally for Volatility
        # Volatility works best with actual filesystem paths
        file_path = storage_service._get_object_path(sample.sha256, sample.filename)

        # NOTE: In a true MinIO-only environment, we would need to download the dump
        # to a temporary local file first. For this implementation, we assume local fallback works.
        # A robust solution downloads it if necessary.

        # Run Volatility
        adapter = Volatility3Adapter(file_path)
        analysis_data = adapter.analyze()

        status = analysis_data.get("status", "failed")
        error_msg = analysis_data.get("error")

        result = MemoryAnalysisResult(
            sample_id=sample.id,
            analysis_status=status,
            error_message=error_msg,
            os_profile=analysis_data.get("os_profile"),
            processes=analysis_data.get("processes", []),
            process_tree=analysis_data.get("process_tree", {}),
            modules=analysis_data.get("modules", []),
            registry=analysis_data.get("registry", []),
            services=analysis_data.get("services", []),
            network_connections=analysis_data.get("network_connections", []),
            handles=analysis_data.get("handles", []),
            command_history=analysis_data.get("command_history", []),
            injected_memory=analysis_data.get("injected_memory", []),
            timeline=analysis_data.get("timeline", []),
        )

        # Update existing or add new
        existing = await self.get_analysis_by_sample_id(db, sample.id)
        if existing:
            await db.delete(existing)
            await db.flush()

        db.add(result)

        # Update sample status
        sample.status = SampleStatus.COMPLETED if status == "completed" else SampleStatus.FAILED

        await db.commit()
        await db.refresh(result)

        return result


memory_service = MemoryAnalysisService()
