# MAP — Static Analysis Service
# Orchestrates the analysis process for PE files and stores results.

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.heuristics import HeuristicsEngine
from app.analysis.models import StaticAnalysisResult
from app.analysis.pe_analyzer import PEAnalyzer
from app.analysis.string_extractor import StringExtractor
from app.core.storage import storage_service
from app.samples.models import Sample, SampleStatus


class StaticAnalysisService:
    """Service for running static analysis on samples."""

    async def get_analysis_by_sample_id(
        self, db: AsyncSession, sample_id: UUID
    ) -> StaticAnalysisResult | None:
        """Retrieve static analysis results for a sample."""
        result = await db.execute(
            select(StaticAnalysisResult).where(StaticAnalysisResult.sample_id == sample_id)
        )
        return result.scalar_one_or_none()

    async def run_analysis(self, db: AsyncSession, sample: Sample) -> StaticAnalysisResult:
        """Run full static analysis on a sample."""

        # 1. Retrieve file data
        file_data = await storage_service.get_file(sample.sha256, sample.filename)
        if not file_data:
            raise ValueError(f"File data not found for sample {sample.id}")

        # 2. Extract Strings
        str_extractor = StringExtractor(file_data)
        strings_data = str_extractor.extract()

        # 3. Analyze PE structure
        pe_analyzer = PEAnalyzer(file_data)
        pe_data = pe_analyzer.analyze()

        if "error" in pe_data:
            # Not a valid PE file, store string extraction only
            result = StaticAnalysisResult(
                sample_id=sample.id, strings=strings_data, heuristic_score=0.0
            )
        else:
            # 4. Run heuristics
            heuristics = HeuristicsEngine(pe_data, strings_data)
            flags, score = heuristics.analyze()

            # Combine suspicious APIs from heuristics
            suspicious_apis = []
            imports = pe_data.get("imports", [])
            all_funcs = set()
            for imp in imports:
                all_funcs.update([f.lower() for f in imp.get("functions", [])])

            suspicious_keywords = [
                "virtualalloc",
                "writeprocessmemory",
                "createremotethread",
                "setwindowshook",
                "isdebuggerpresent",
            ]

            for func in all_funcs:
                for keyword in suspicious_keywords:
                    if keyword in func:
                        suspicious_apis.append(func)

            # 5. Create result record
            result = StaticAnalysisResult(
                sample_id=sample.id,
                headers=pe_data.get("headers", {}),
                sections=pe_data.get("sections", []),
                imports=pe_data.get("imports", []),
                exports=pe_data.get("exports", []),
                resources=pe_data.get("resources", []),
                strings=strings_data,
                entropy_score=sample.entropy,
                suspicious_apis=list(set(suspicious_apis)),
                heuristic_flags=flags,
                heuristic_score=score,
                entry_point=pe_data.get("entry_point"),
                image_base=pe_data.get("image_base"),
                timestamp=pe_data.get("timestamp"),
            )

        # Update existing or add new
        existing = await self.get_analysis_by_sample_id(db, sample.id)
        if existing:
            await db.delete(existing)
            await db.flush()

        db.add(result)

        # Update sample status
        sample.status = SampleStatus.COMPLETED
        await db.commit()
        await db.refresh(result)

        return result


analysis_service = StaticAnalysisService()
