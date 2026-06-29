import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.memory.models import MemoryAnalysisResult
from app.memory.vol3_adapter import vol3_adapter
from app.core.storage import storage_service
from app.samples.models import Sample

class MemoryService:
    @staticmethod
    async def run_memory_analysis(sample_id: str, session: AsyncSession) -> MemoryAnalysisResult:
        sample_uuid = uuid.UUID(sample_id)
        
        # Get sample
        result = await session.execute(select(Sample).where(Sample.id == sample_uuid))
        sample = result.scalars().first()
        
        if not sample:
            raise ValueError(f"Sample {sample_id} not found")
            
        # Note: In a real system, we'd fetch the memory dump file.
        # Here we mock the dump path
        dump_path = "/tmp/mock_dump.vmem"
        
        # Run Volatility
        vol_results = vol3_adapter.analyze_memory_dump(dump_path)
        
        analysis = MemoryAnalysisResult(
            sample_id=sample_uuid,
            processes=vol_results.get("processes", []),
            modules=vol_results.get("modules", []),
            network_connections=vol_results.get("network_connections", []),
            injected_memory=[],
            registry=[],
            timeline=[],
            completed_at=datetime.utcnow()
        )
        
        session.add(analysis)
        await session.commit()
        await session.refresh(analysis)
        
        return analysis

memory_service = MemoryService()
