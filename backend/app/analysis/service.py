import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.analysis.models import StaticAnalysisResult
from app.analysis.pe_analyzer import analyze_pe
from app.analysis.string_extractor import extract_strings
from app.analysis.heuristics import run_heuristics
from app.core.storage import storage_service
from app.samples.models import Sample


class AnalysisService:
    @staticmethod
    async def run_static_analysis(sample_id: str, session: AsyncSession) -> StaticAnalysisResult:
        """Run full static analysis pipeline for a sample."""
        
        # 1. Get sample
        sample_uuid = uuid.UUID(sample_id)
        result = await session.execute(select(Sample).where(Sample.id == sample_uuid))
        sample = result.scalars().first()
        
        if not sample:
            raise ValueError(f"Sample {sample_id} not found")
            
        # 2. Get file content from storage
        try:
            content = await storage_service.get_file(sample.sha256)
        except Exception as e:
            raise ValueError(f"Failed to read file from storage: {str(e)}")
            
        # Write to temporary file for pefile to process
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
            
        try:
            # 3. Analyze PE structure
            pe_data = analyze_pe(tmp_path)
            
            # 4. Extract strings
            strings_data = extract_strings(content)
            
            # 5. Run heuristics
            heuristics = run_heuristics(pe_data)
            
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
                
        # 6. Save results
        analysis = StaticAnalysisResult(
            sample_id=sample_uuid,
            headers=pe_data.get("headers", {}),
            sections=pe_data.get("sections", []),
            imports=pe_data.get("imports", {}),
            exports=pe_data.get("exports", []),
            compiler=pe_data.get("compiler", "Unknown"),
            strings=strings_data,
            heuristic_flags=heuristics,
            completed_at=datetime.utcnow()
        )
        
        session.add(analysis)
        
        # Update sample status
        sample.status = "analyzed"
        
        await session.commit()
        await session.refresh(analysis)
        
        return analysis


analysis_service = AnalysisService()
